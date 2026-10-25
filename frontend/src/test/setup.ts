import '@testing-library/jest-dom';

// Polyfill window.ResizeObserver for Recharts
(globalThis as any).ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};
