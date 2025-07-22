import { render, screen } from '@testing-library/react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '../Card'

describe('Card Components', () => {
  it('renders Card with children', () => {
    render(
      <Card data-testid="card">
        <div>Card Content</div>
      </Card>
    )

    const card = screen.getByTestId('card')
    expect(card).toBeInTheDocument()
    expect(screen.getByText('Card Content')).toBeInTheDocument()
  })

  it('applies custom className to Card', () => {
    render(
      <Card className="custom-class" data-testid="card">
        Content
      </Card>
    )

    const card = screen.getByTestId('card')
    expect(card).toHaveClass('custom-class')
  })

  it('renders CardHeader with children', () => {
    render(
      <CardHeader data-testid="card-header">
        <div>Header Content</div>
      </CardHeader>
    )

    const header = screen.getByTestId('card-header')
    expect(header).toBeInTheDocument()
    expect(screen.getByText('Header Content')).toBeInTheDocument()
  })

  it('renders CardTitle with text', () => {
    render(<CardTitle>Test Title</CardTitle>)
    expect(screen.getByText('Test Title')).toBeInTheDocument()
  })

  it('renders CardDescription with text', () => {
    render(<CardDescription>Test Description</CardDescription>)
    expect(screen.getByText('Test Description')).toBeInTheDocument()
  })

  it('renders CardContent with children', () => {
    render(
      <CardContent data-testid="card-content">
        <div>Content</div>
      </CardContent>
    )

    const content = screen.getByTestId('card-content')
    expect(content).toBeInTheDocument()
    expect(screen.getByText('Content')).toBeInTheDocument()
  })

  it('renders CardFooter with children', () => {
    render(
      <CardFooter data-testid="card-footer">
        <div>Footer</div>
      </CardFooter>
    )

    const footer = screen.getByTestId('card-footer')
    expect(footer).toBeInTheDocument()
    expect(screen.getByText('Footer')).toBeInTheDocument()
  })

  it('renders complete Card structure', () => {
    render(
      <Card data-testid="complete-card">
        <CardHeader>
          <CardTitle>Card Title</CardTitle>
          <CardDescription>Card Description</CardDescription>
        </CardHeader>
        <CardContent>
          <p>Card content goes here</p>
        </CardContent>
        <CardFooter>
          <button>Action</button>
        </CardFooter>
      </Card>
    )

    expect(screen.getByTestId('complete-card')).toBeInTheDocument()
    expect(screen.getByText('Card Title')).toBeInTheDocument()
    expect(screen.getByText('Card Description')).toBeInTheDocument()
    expect(screen.getByText('Card content goes here')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Action' })).toBeInTheDocument()
  })
})