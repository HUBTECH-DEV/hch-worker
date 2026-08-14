export function deriveWorkerControlView(status) {
  const requestedCapacity = Number.isInteger(status?.capacity?.requestedCapacity)
    ? status.capacity.requestedCapacity
    : null;
  const activeAssignments = Number.isInteger(status?.capacity?.activeAssignments)
    ? status.capacity.activeAssignments
    : 0;
  const operatorControl = status?.operatorControl;
  if (operatorControl?.status === "invalid") {
    return Object.freeze({
      source: "operator-control-invalid",
      mode: "invalid",
      acceptingClaims: null,
      drainRequested: null,
      activeAssignments,
      canStart: false,
      canPause: false,
      canStop: false,
      requestedParallelism: null,
      lastNonZeroParallelism: null,
    });
  }

  const authoritative = operatorControl?.status === "valid";
  const acceptingClaims = authoritative
    ? operatorControl.acceptingClaims === true
    : requestedCapacity !== null && requestedCapacity > 0;
  const drainRequested = authoritative
    ? operatorControl.drainRequested === true
    : !acceptingClaims;
  const mode = acceptingClaims && !drainRequested
    ? "active"
    : activeAssignments > 0 ? "draining" : "paused";
  return Object.freeze({
    source: authoritative ? "operator-control" : "capacity-fallback",
    mode,
    acceptingClaims,
    drainRequested,
    activeAssignments,
    canStart: !acceptingClaims && drainRequested,
    canPause: acceptingClaims && !drainRequested,
    canStop: activeAssignments > 0 || acceptingClaims,
    requestedParallelism: authoritative ? operatorControl.requestedParallelism : requestedCapacity,
    lastNonZeroParallelism: authoritative ? operatorControl.lastNonZeroParallelism : null,
  });
}
