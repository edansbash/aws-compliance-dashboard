/**
 * Date/time formatting utilities with configurable timezone support.
 *
 * Set VITE_DISPLAY_TIMEZONE environment variable to control display timezone.
 * Examples: "America/New_York" (EST/EDT), "America/Los_Angeles" (PST/PDT), "UTC"
 *
 * Database times remain in UTC - this only affects display formatting.
 */

/** Get configured display timezone from environment, defaults to browser local */
export const getDisplayTimezone = (): string | undefined => {
  const tz = import.meta.env.VITE_DISPLAY_TIMEZONE;
  return tz && tz.trim() !== '' ? tz.trim() : undefined;
};

/** Common format options with timezone */
const getFormatOptions = (options: Intl.DateTimeFormatOptions = {}): Intl.DateTimeFormatOptions => {
  const timezone = getDisplayTimezone();
  return timezone ? { ...options, timeZone: timezone } : options;
};

/**
 * Parse a date string as UTC if it doesn't have a timezone indicator.
 * Database dates are stored in UTC but may be returned without the 'Z' suffix.
 */
const parseAsUTC = (dateStr: string): Date => {
  // If string already has timezone info (Z, +, or -), parse as-is
  if (/[Z+-]/.test(dateStr.slice(-6))) {
    return new Date(dateStr);
  }
  // Otherwise, append Z to treat as UTC
  return new Date(dateStr + 'Z');
};

/**
 * Format a date string or Date object as full date + time.
 * Example: "1/15/2024, 2:30:45 PM EST"
 */
export const formatDateTime = (dateInput: string | Date | null | undefined): string => {
  if (!dateInput) return '-';
  const date = typeof dateInput === 'string' ? parseAsUTC(dateInput) : dateInput;
  if (isNaN(date.getTime())) return '-';
  return date.toLocaleString('en-US', getFormatOptions({ timeZoneName: 'short' }));
};

/**
 * Format a date string or Date object as date only.
 * Example: "1/15/2024"
 */
export const formatDate = (dateInput: string | Date | null | undefined): string => {
  if (!dateInput) return '-';
  const date = typeof dateInput === 'string' ? parseAsUTC(dateInput) : dateInput;
  if (isNaN(date.getTime())) return '-';
  return date.toLocaleDateString('en-US', getFormatOptions());
};

/**
 * Format a date string or Date object as time only (2-digit hour:minute).
 * Example: "02:30 PM"
 */
export const formatTime = (dateInput: string | Date | null | undefined): string => {
  if (!dateInput) return '-';
  const date = typeof dateInput === 'string' ? parseAsUTC(dateInput) : dateInput;
  if (isNaN(date.getTime())) return '-';
  return date.toLocaleTimeString('en-US', getFormatOptions({
    hour: '2-digit',
    minute: '2-digit'
  }));
};

/**
 * Format a date string or Date object as relative time.
 * Example: "5m ago", "2h ago", "3d ago"
 */
export const formatTimeAgo = (dateInput: string | Date | null | undefined): string => {
  if (!dateInput) return '-';
  const date = typeof dateInput === 'string' ? parseAsUTC(dateInput) : dateInput;
  if (isNaN(date.getTime())) return '-';

  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
};

/**
 * Get ISO date string (YYYY-MM-DD) for filenames.
 * This uses UTC to ensure consistent filenames regardless of timezone.
 */
export const getISODateForFilename = (date: Date = new Date()): string => {
  return date.toISOString().split('T')[0];
};

/**
 * Extract date portion from ISO string for form inputs (YYYY-MM-DD).
 */
export const extractDateForInput = (dateInput: string | null | undefined): string => {
  if (!dateInput) return '';
  return dateInput.split('T')[0];
};
