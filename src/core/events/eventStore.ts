/**
 * PhishGuard Security Event Store
 * 
 * Manages bounded, in-memory & session-backed security events per tab.
 * Ensures the background service worker can reconstruct timelines and correlate
 * events without persisting any sensitive credentials or payload data.
 */

import { BaseSecurityEvent, ThreatSeverity } from './eventTypes';

const MAX_EVENTS_PER_TAB = 50;

export class SecurityEventStore {
  private tabEvents: Map<number, BaseSecurityEvent[]> = new Map();

  /**
   * Records a security event for a specific browser tab
   */
  public recordEvent(event: BaseSecurityEvent): void {
    const tabId = event.tabId;
    if (!this.tabEvents.has(tabId)) {
      this.tabEvents.set(tabId, []);
    }

    const events = this.tabEvents.get(tabId)!;
    events.push(event);

    // Keep bounded history to avoid memory growth
    if (events.length > MAX_EVENTS_PER_TAB) {
      events.shift();
    }
  }

  /**
   * Retrieves all recorded security events for a tab in chronological order
   */
  public getTabEvents(tabId: number): BaseSecurityEvent[] {
    return [...(this.tabEvents.get(tabId) || [])];
  }

  /**
   * Cleans up events when a tab is closed
   */
  public clearTab(tabId: number): void {
    this.tabEvents.delete(tabId);
  }

  /**
   * Returns the most recent events across all active tabs
   */
  public getRecentEvents(limit: number = 20): BaseSecurityEvent[] {
    const allEvents: BaseSecurityEvent[] = [];
    for (const events of this.tabEvents.values()) {
      allEvents.push(...events);
    }
    return allEvents.sort((a, b) => b.timestamp - a.timestamp).slice(0, limit);
  }

  /**
   * Returns whether any events of high or critical severity were recorded for this tab
   */
  public hasHighSeverityEvents(tabId: number): boolean {
    const events = this.tabEvents.get(tabId) || [];
    return events.some(e => e.severity === 'HIGH' || e.severity === 'CRITICAL');
  }
}

// Global in-memory singleton for runtime usage
export const globalEventStore = new SecurityEventStore();
