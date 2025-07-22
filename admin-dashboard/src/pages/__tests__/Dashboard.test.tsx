import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Dashboard } from '../Dashboard'

// Mock the API module
jest.mock('@/lib/api', () => ({
  adminApi: {
    getSystemStatus: jest.fn(() => Promise.resolve({ data: { status: 'healthy' } })),
    getSystemDiagnostics: jest.fn(() => Promise.resolve({ 
      data: { 
        gateway_status: 'healthy',
        system_resources: {
          cpu_usage_percent: 45,
          memory_usage_bytes: 1000000,
          memory_total_bytes: 2000000,
          disk_usage_bytes: 500000,
          disk_total_bytes: 1000000,
        }
      } 
    })),
    getServices: jest.fn(() => Promise.resolve({ 
      data: { 
        total_services: 5,
        services: [
          { name: 'test-service', healthy_instances: 2, instance_count: 2 }
        ]
      } 
    })),
    getMetricsSummary: jest.fn(() => Promise.resolve({ 
      data: { 
        total_requests: 1000,
        error_rate: 0.05,
        avg_response_time: 150,
        active_connections: 25
      } 
    })),
    getAuditStatistics: jest.fn(() => Promise.resolve({ data: { total_changes: 10 } })),
  }
}))

// Mock recharts components
jest.mock('recharts', () => ({
  LineChart: ({ children }: any) => <div data-testid="line-chart">{children}</div>,
  Line: () => <div data-testid="line" />,
  AreaChart: ({ children }: any) => <div data-testid="area-chart">{children}</div>,
  Area: () => <div data-testid="area" />,
  XAxis: () => <div data-testid="x-axis" />,
  YAxis: () => <div data-testid="y-axis" />,
  CartesianGrid: () => <div data-testid="cartesian-grid" />,
  Tooltip: () => <div data-testid="tooltip" />,
  ResponsiveContainer: ({ children }: any) => <div data-testid="responsive-container">{children}</div>,
}))

const createTestQueryClient = () => new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
    },
  },
})

const renderWithQueryClient = (component: React.ReactElement) => {
  const queryClient = createTestQueryClient()
  return render(
    <QueryClientProvider client={queryClient}>
      {component}
    </QueryClientProvider>
  )
}

describe('Dashboard', () => {
  it('renders dashboard header', () => {
    renderWithQueryClient(<Dashboard />)
    
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Overview of your API Gateway performance and health')).toBeInTheDocument()
  })

  it('renders key metrics cards', () => {
    renderWithQueryClient(<Dashboard />)
    
    expect(screen.getByText('Total Services')).toBeInTheDocument()
    expect(screen.getByText('Healthy Instances')).toBeInTheDocument()
    expect(screen.getByText('Total Requests')).toBeInTheDocument()
    expect(screen.getByText('Error Rate')).toBeInTheDocument()
  })

  it('renders charts', () => {
    renderWithQueryClient(<Dashboard />)
    
    expect(screen.getByText('Request Metrics')).toBeInTheDocument()
    expect(screen.getByText('System Health')).toBeInTheDocument()
    expect(screen.getAllByTestId('responsive-container')).toHaveLength(2)
  })

  it('renders system status section', () => {
    renderWithQueryClient(<Dashboard />)
    
    expect(screen.getByText('System Status')).toBeInTheDocument()
  })

  it('renders resource usage section', () => {
    renderWithQueryClient(<Dashboard />)
    
    expect(screen.getByText('Resource Usage')).toBeInTheDocument()
  })

  it('renders recent activity section', () => {
    renderWithQueryClient(<Dashboard />)
    
    expect(screen.getByText('Recent Activity')).toBeInTheDocument()
  })
})