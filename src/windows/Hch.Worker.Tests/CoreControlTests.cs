using Hch.Worker.Core;

namespace Hch.Worker.Tests;

public sealed class CoreControlTests
{
    [Fact]
    public void InstallationStartsNotReadyAndPausedAtZero()
    {
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 4, claimBatchSize: 3);

        var initial = control.Snapshot;
        Assert.Equal(WorkerOperationalState.NotReady, initial.State);
        Assert.False(initial.AcceptingClaims);
        Assert.Equal(0, initial.MaxConcurrentJobs);

        var ready = control.MarkReady();
        Assert.Equal(WorkerOperationalState.Paused, ready.State);
        Assert.Equal(0, ready.MaxConcurrentJobs);
        Assert.False(ready.AcceptingClaims);
    }

    [Fact]
    public void StartRestoresLastNonZeroParallelismAndPauseDoesNotCancelActiveJobs()
    {
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 4);
        control.MarkReady();
        control.SetGrantedCapacity(4);
        var running = control.Start();
        Assert.Equal(4, running.MaxConcurrentJobs);

        Assert.True(control.TryReserveSlot());
        control.ActivateReservation();
        var pausing = control.Pause();

        Assert.Equal(WorkerOperationalState.Pausing, pausing.State);
        Assert.Equal(1, pausing.ActiveJobs);
        Assert.Equal(0, pausing.MaxConcurrentJobs);
        Assert.False(pausing.AcceptingClaims);

        var paused = control.FinishJob();
        Assert.Equal(WorkerOperationalState.Paused, paused.State);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(65)]
    public void ParallelismOutsideZeroThroughSixtyFourIsRejected(int value)
    {
        var control = new WorkerControlState();
        control.MarkReady();
        Assert.Throws<ArgumentOutOfRangeException>(() => control.SetMaxConcurrentJobs(value));
    }

    [Fact]
    public void EffectiveCapacitySeparatesRequestedGrantedActiveAndReserved()
    {
        var control = new WorkerControlState(lastNonZeroMaxConcurrentJobs: 6);
        control.MarkReady();
        control.Start();
        control.SetGrantedCapacity(4);
        Assert.True(control.TryReserveSlot());
        Assert.True(control.TryReserveSlot());
        control.ActivateReservation();

        var snapshot = control.Snapshot;
        Assert.Equal(6, snapshot.MaxConcurrentJobs);
        Assert.Equal(4, snapshot.GrantedCapacity);
        Assert.Equal(1, snapshot.ActiveJobs);
        Assert.Equal(1, snapshot.ReservedJobs);
        Assert.Equal(2, snapshot.AvailableSlots);
    }
}
