const MAX_EVENTS_PER_TAB = 50;
class SecurityEventStore {
  constructor() {
    this.tabEvents = /* @__PURE__ */ new Map();
  }
  /**
   * Records a security event for a specific browser tab
   */
  recordEvent(event) {
    const tabId = event.tabId;
    if (!this.tabEvents.has(tabId)) {
      this.tabEvents.set(tabId, []);
    }
    const events = this.tabEvents.get(tabId);
    events.push(event);
    if (events.length > MAX_EVENTS_PER_TAB) {
      events.shift();
    }
  }
  /**
   * Retrieves all recorded security events for a tab in chronological order
   */
  getTabEvents(tabId) {
    return [...this.tabEvents.get(tabId) || []];
  }
  /**
   * Cleans up events when a tab is closed
   */
  clearTab(tabId) {
    this.tabEvents.delete(tabId);
  }
  /**
   * Returns the most recent events across all active tabs
   */
  getRecentEvents(limit = 20) {
    const allEvents = [];
    for (const events of this.tabEvents.values()) {
      allEvents.push(...events);
    }
    return allEvents.sort((a, b) => b.timestamp - a.timestamp).slice(0, limit);
  }
  /**
   * Returns whether any events of high or critical severity were recorded for this tab
   */
  hasHighSeverityEvents(tabId) {
    const events = this.tabEvents.get(tabId) || [];
    return events.some((e) => e.severity === "HIGH" || e.severity === "CRITICAL");
  }
}
const globalEventStore = new SecurityEventStore();
export {
  SecurityEventStore,
  globalEventStore
};
