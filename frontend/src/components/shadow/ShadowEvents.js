/**
 * ShadowEvents.js
 * Decoupled Application Event Bus mapping application events to SHADOW mascot states.
 */

import { SHADOW_STATES } from './ShadowConstants';

export const SHADOW_APP_EVENTS = {
  DASHBOARD_LOADED: 'DASHBOARD_LOADED',
  SCAN_STARTED: 'SCAN_STARTED',
  SCAN_ANALYZING: 'SCAN_ANALYZING',
  SCAN_COMPLETED_CLEAN: 'SCAN_COMPLETED_CLEAN',
  SCAN_COMPLETED_SUSPICIOUS: 'SCAN_COMPLETED_SUSPICIOUS',
  SCAN_COMPLETED_MALICIOUS: 'SCAN_COMPLETED_MALICIOUS',
  REPORT_GENERATING: 'REPORT_GENERATING',
  REPORT_COMPLETED: 'REPORT_COMPLETED',
  APPLICATION_ERROR: 'APPLICATION_ERROR',
  USER_INACTIVE_TIMEOUT: 'USER_INACTIVE_TIMEOUT',
  USER_INTERACTION_WAKE: 'USER_INTERACTION_WAKE',
};

class ShadowEventBus {
  constructor() {
    this.listeners = new Map();
    this.eventToStateMap = {
      [SHADOW_APP_EVENTS.DASHBOARD_LOADED]: SHADOW_STATES.IDLE,
      [SHADOW_APP_EVENTS.SCAN_STARTED]: SHADOW_STATES.ATTENTION,
      [SHADOW_APP_EVENTS.SCAN_ANALYZING]: SHADOW_STATES.THINKING,
      [SHADOW_APP_EVENTS.SCAN_COMPLETED_CLEAN]: SHADOW_STATES.SUCCESS,
      [SHADOW_APP_EVENTS.SCAN_COMPLETED_SUSPICIOUS]: SHADOW_STATES.WARNING,
      [SHADOW_APP_EVENTS.SCAN_COMPLETED_MALICIOUS]: SHADOW_STATES.ALERT,
      [SHADOW_APP_EVENTS.REPORT_GENERATING]: SHADOW_STATES.THINKING,
      [SHADOW_APP_EVENTS.REPORT_COMPLETED]: SHADOW_STATES.SUCCESS,
      [SHADOW_APP_EVENTS.APPLICATION_ERROR]: SHADOW_STATES.ERROR,
      [SHADOW_APP_EVENTS.USER_INACTIVE_TIMEOUT]: SHADOW_STATES.SLEEPING,
      [SHADOW_APP_EVENTS.USER_INTERACTION_WAKE]: SHADOW_STATES.ATTENTION,
    };
  }

  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event).add(callback);
    return () => {
      this.listeners.get(event)?.delete(callback);
    };
  }

  emit(event, data = null) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).forEach((cb) => cb(data));
    }
  }

  getStateForEvent(event) {
    return this.eventToStateMap[event] || SHADOW_STATES.IDLE;
  }
}

export const shadowEventBus = new ShadowEventBus();
