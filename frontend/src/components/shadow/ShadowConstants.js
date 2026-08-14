/**
 * ShadowConstants.js
 * Production definitions, expression states, priority hierarchy, and defaults for the SHADOW Coded Companion.
 */

export const SHADOW_STATES = {
  IDLE: 'idle',
  ATTENTION: 'attention',
  HAPPY: 'happy',
  CURIOUS: 'curious',
  THINKING: 'thinking',
  TALKING: 'talking',
  ALERT: 'alert',
  WARNING: 'warning',
  CONFUSED: 'confused',
  SLEEPING: 'sleeping',
  SURPRISED: 'surprised',
  FOCUSED: 'focused',
  SUCCESS: 'success',
  ERROR: 'error',
};

export const VALID_SHADOW_STATES = Object.values(SHADOW_STATES);

/**
 * State Priority Order (Higher index = higher priority)
 * High priority states (e.g. ERROR, ALERT) cannot be overridden by lower priority micro-behaviors.
 */
export const STATE_PRIORITIES = {
  [SHADOW_STATES.SLEEPING]: 1,
  [SHADOW_STATES.IDLE]: 2,
  [SHADOW_STATES.CURIOUS]: 3,
  [SHADOW_STATES.FOCUSED]: 4,
  [SHADOW_STATES.HAPPY]: 4,
  [SHADOW_STATES.SUCCESS]: 5,
  [SHADOW_STATES.ATTENTION]: 6,
  [SHADOW_STATES.THINKING]: 7,
  [SHADOW_STATES.CONFUSED]: 8,
  [SHADOW_STATES.TALKING]: 8,
  [SHADOW_STATES.WARNING]: 9,
  [SHADOW_STATES.ALERT]: 10,
  [SHADOW_STATES.ERROR]: 11,
};

export const DEFAULT_STORAGE_KEY = 'shadow-companion-position';

export const MASCOT_DIMENSIONS = {
  DESKTOP: { width: 136, height: 170 },
  LAPTOP: { width: 120, height: 150 },
  MOBILE: { width: 96, height: 120 },
};
