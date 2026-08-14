export function deriveBatchProgress(batch, workload, adaptiveWork) {
  const totalItems = Math.max(0, Number(batch?.totalJobs) || 0);
  const runningItems = Math.min(totalItems, Math.max(0, Number(workload?.jobsRunning) || 0));
  const activeItem = Array.isArray(adaptiveWork?.activeWork) ? adaptiveWork.activeWork[0] ?? null : null;
  const itemPercent = clampPercent(activeItem?.progressPercent);

  return Object.freeze({
    itemPercent,
    runningItems,
    totalItems,
    itemsPercent: totalItems === 0 ? 0 : Math.round((runningItems / totalItems) * 100),
  });
}

function clampPercent(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? Math.min(100, Math.max(0, Math.round(numeric))) : 0;
}
