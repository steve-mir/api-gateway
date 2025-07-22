import { render, screen, fireEvent } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'
import { Layout } from '../Layout'

const MockLayout = ({ children }: { children: React.ReactNode }) => (
  <BrowserRouter>
    <Layout>{children}</Layout>
  </BrowserRouter>
)

describe('Layout', () => {
  it('renders the main navigation', () => {
    render(
      <MockLayout>
        <div>Test Content</div>
      </MockLayout>
    )

    expect(screen.getByText('API Gateway Admin')).toBeInTheDocument()
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Services')).toBeInTheDocument()
    expect(screen.getByText('Configuration')).toBeInTheDocument()
    expect(screen.getByText('Metrics')).toBeInTheDocument()
    expect(screen.getByText('Logs')).toBeInTheDocument()
    expect(screen.getByText('Alerts')).toBeInTheDocument()
    expect(screen.getByText('Users')).toBeInTheDocument()
  })

  it('renders children content', () => {
    render(
      <MockLayout>
        <div>Test Content</div>
      </MockLayout>
    )

    expect(screen.getByText('Test Content')).toBeInTheDocument()
  })

  it('shows mobile menu button on small screens', () => {
    render(
      <MockLayout>
        <div>Test Content</div>
      </MockLayout>
    )

    // The mobile menu button should be present (though hidden on desktop)
    const menuButtons = screen.getAllByRole('button')
    expect(menuButtons.length).toBeGreaterThan(0)
  })

  it('displays gateway status', () => {
    render(
      <MockLayout>
        <div>Test Content</div>
      </MockLayout>
    )

    expect(screen.getByText('Gateway Online')).toBeInTheDocument()
  })
})