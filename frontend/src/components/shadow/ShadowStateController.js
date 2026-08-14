/**
 * ShadowStateController.js
 * Production Centralized Priority State Machine, Micro-Behavior Scheduler, & Eye-Tracking Engine.
 */

import { SHADOW_STATES, STATE_PRIORITIES, VALID_SHADOW_STATES } from './ShadowConstants';

class ShadowStateController {
  constructor() {
    this.currentState = SHADOW_STATES.IDLE;
    this.isBlinking = false;
    this.eyeOffset = { x: 0, y: 0 };
    this.microTilt = 0;
    this.listeners = new Set();
    this.microSchedulerTimer = null;
    this.enableMicroBehaviors = true;
    this.enableEyeTracking = true;

    this.startMicroScheduler();
  }

  getCurrentState() {
    return this.currentState;
  }

  setState(newState, force = false) {
    if (!VALID_SHADOW_STATES.includes(newState)) {
      console.warn(`[ShadowStateController] Invalid state "${newState}". Defaulting to idle.`);
      newState = SHADOW_STATES.IDLE;
    }

    const currentPriority = STATE_PRIORITIES[this.currentState] || 1;
    const newPriority = STATE_PRIORITIES[newState] || 1;

    // Force override or priority-based transition
    if (force || newPriority >= currentPriority || this.currentState === SHADOW_STATES.IDLE || this.currentState === SHADOW_STATES.SLEEPING) {
      this.currentState = newState;
      this.notifyListeners();
    }
  }

  subscribe(listener) {
    this.listeners.add(listener);
    listener({
      state: this.currentState,
      isBlinking: this.isBlinking,
      eyeOffset: this.eyeOffset,
      microTilt: this.microTilt,
    });

    return () => {
      this.listeners.delete(listener);
    };
  }

  notifyListeners() {
    const payload = {
      state: this.currentState,
      isBlinking: this.isBlinking,
      eyeOffset: this.eyeOffset,
      microTilt: this.microTilt,
    };
    this.listeners.forEach((cb) => cb(payload));
  }

  // Eye-Tracking Cursor Offset Calculator (clamped safely inside visor screen bounds)
  updateCursorTracking(cursorX, cursorY, mascotRect) {
    if (!this.enableEyeTracking || !mascotRect) return;

    const mascotCenterX = mascotRect.left + mascotRect.width / 2;
    const mascotCenterY = mascotRect.top + mascotRect.height / 3;

    const dx = cursorX - mascotCenterX;
    const dy = cursorY - mascotCenterY;
    const dist = Math.hypot(dx, dy);

    // Limit maximum eye displacement within helmet screen visor (-8px to +8px max)
    const maxOffset = 8;
    let newX = 0;
    let newY = 0;
    if (dist > 0) {
      const clampedX = Math.min(Math.max((dx / dist) * Math.min(dist / 60, maxOffset), -maxOffset), maxOffset);
      const clampedY = Math.min(Math.max((dy / dist) * Math.min(dist / 60, maxOffset), -maxOffset), maxOffset);
      newX = Math.round(clampedX * 10) / 10;
      newY = Math.round(clampedY * 10) / 10;
    }

    if (this.eyeOffset.x === newX && this.eyeOffset.y === newY) {
      return;
    }

    this.eyeOffset = { x: newX, y: newY };
    this.notifyListeners();
  }

  resetEyeOffset() {
    this.eyeOffset = { x: 0, y: 0 };
    this.notifyListeners();
  }

  // Micro-Behavior Scheduler (Controlled randomness for organic aliveness)
  startMicroScheduler() {
    const scheduleNext = () => {
      if (!this.enableMicroBehaviors) {
        this.microSchedulerTimer = setTimeout(scheduleNext, 3000);
        return;
      }

      // Do not interrupt active non-idle states
      if (
        this.currentState === SHADOW_STATES.IDLE ||
        this.currentState === SHADOW_STATES.CURIOUS ||
        this.currentState === SHADOW_STATES.FOCUSED
      ) {
        const actionType = Math.random();

        if (actionType < 0.55) {
          // Perform random blink (160ms)
          this.isBlinking = true;
          this.notifyListeners();
          setTimeout(() => {
            this.isBlinking = false;
            this.notifyListeners();
          }, 160);
        } else if (actionType < 0.8) {
          // Perform micro glance offset
          const randomGlanceX = (Math.random() - 0.5) * 10;
          const randomGlanceY = (Math.random() - 0.5) * 6;
          this.eyeOffset = { x: Math.round(randomGlanceX), y: Math.round(randomGlanceY) };
          this.notifyListeners();
          setTimeout(() => {
            this.eyeOffset = { x: 0, y: 0 };
            this.notifyListeners();
          }, 1200);
        } else {
          // Perform micro head tilt shift (-2.5 deg to +2.5 deg)
          this.microTilt = (Math.random() - 0.5) * 5;
          this.notifyListeners();
          setTimeout(() => {
            this.microTilt = 0;
            this.notifyListeners();
          }, 2000);
        }
      }

      const randomInterval = Math.floor(Math.random() * 3200) + 2800;
      this.microSchedulerTimer = setTimeout(scheduleNext, randomInterval);
    };

    scheduleNext();
  }

  stopMicroScheduler() {
    if (this.microSchedulerTimer) {
      clearTimeout(this.microSchedulerTimer);
    }
  }
}

export const shadowStateController = new ShadowStateController();
