import '@testing-library/jest-dom'

// Mock IntersectionObserver
global.IntersectionObserver = class IntersectionObserver {
  constructor() {}
  disconnect() {}
  observe() {}
  unobserve() {}
}

// Mock ResizeObserver
global.ResizeObserver = class ResizeObserver {
  constructor() {}
  disconnect() {}
  observe() {}
  unobserve() {}
}

// Mock matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: jest.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: jest.fn(), // deprecated
    removeListener: jest.fn(), // deprecated
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    dispatchEvent: jest.fn(),
  })),
})

// Mock HTMLCanvasElement.getContext
HTMLCanvasElement.prototype.getContext = jest.fn()

// Mock vis-network
jest.mock('vis-network', () => ({
  Network: jest.fn().mockImplementation(() => ({
    on: jest.fn(),
    off: jest.fn(),
    destroy: jest.fn(),
    getScale: jest.fn(() => 1),
    moveTo: jest.fn(),
    fit: jest.fn(),
    canvas: {
      frame: {
        canvas: {
          toDataURL: jest.fn(() => 'data:image/png;base64,mock')
        }
      }
    }
  }))
}))

// Mock vis-data
jest.mock('vis-data', () => ({
  DataSet: jest.fn().mockImplementation((data) => ({
    add: jest.fn(),
    update: jest.fn(),
    remove: jest.fn(),
    clear: jest.fn(),
    get: jest.fn(() => data || []),
    getIds: jest.fn(() => []),
    length: data?.length || 0
  }))
}))

// Mock Monaco Editor
jest.mock('@monaco-editor/react', () => ({
  Editor: ({ onChange, value }: any) => (
    <textarea
      data-testid="monaco-editor"
      value={value}
      onChange={(e) => onChange?.(e.target.value)}
    />
  )
}))

// Mock react-json-view
jest.mock('react-json-view', () => {
  return function MockReactJsonView({ src }: any) {
    return <pre data-testid="json-view">{JSON.stringify(src, null, 2)}</pre>
  }
})