// The permit belongs to inference, not to the HTTP socket. A disconnected
// caller cannot admit another maintenance request while computation is live.
export function createMaintenanceAdmission() {
  let active = false;
  return {
    async run(work) {
      if (active) return { accepted: false };
      active = true;
      try { return { accepted: true, value: await work() }; }
      finally { active = false; }
    },
  };
}
