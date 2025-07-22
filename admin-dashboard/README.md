# API Gateway Admin Dashboard

A modern, responsive admin dashboard for managing the Rust API Gateway. Built with React, TypeScript, and Tailwind CSS.

## Features

### 🏠 Dashboard
- Real-time system metrics and health monitoring
- Interactive charts showing request volume, response times, and system health
- Key performance indicators (KPIs) with trend indicators
- Recent activity feed
- Resource usage monitoring (CPU, memory, disk)

### 🔧 Services Management
- View all registered service instances
- Add, edit, and delete services
- Health status monitoring with real-time updates
- Service filtering by health status and protocol
- Bulk operations for multiple services
- Service metadata management

### 🌐 Service Topology
- Interactive network visualization of service relationships
- Real-time health status indicators
- Hierarchical and physics-based layout options
- Protocol filtering and node customization
- Export topology diagrams
- Detailed service information on selection

### ⚙️ Configuration Management
- Visual and JSON configuration editors
- Real-time configuration validation
- Configuration backup and restore
- Change history and audit trail
- Diff view for configuration changes
- Hot reload configuration without restart

### 📊 Metrics Dashboard
- Comprehensive metrics visualization with multiple chart types
- Real-time data updates
- Time range selection (1h, 6h, 24h, 7d)
- Status code distribution
- Top endpoints analysis
- System health monitoring
- Export metrics data

### 📝 Logs Management
- Real-time log viewer with filtering and search
- System logs and audit logs in separate tabs
- Log level filtering (error, warn, info, debug)
- Audit event type filtering
- Export logs functionality
- Detailed log entry inspection

### 🚨 Alert Management
- Create and manage alert rules
- Multiple alert conditions (>, <, =, !=, >=, <=)
- Metric-based alerting
- Enable/disable alert rules
- Test alert functionality
- Recent alert activity tracking

### 👥 User Management
- Admin user account management
- Role-based access control (Super Admin, Admin, Operator, Viewer)
- User activation/deactivation
- Permission management
- Role-based UI restrictions

## Technology Stack

- **Frontend Framework**: React 18 with TypeScript
- **Styling**: Tailwind CSS with custom design system
- **State Management**: TanStack Query (React Query) for server state
- **Charts**: Recharts for data visualization
- **Network Visualization**: vis-network for service topology
- **Code Editor**: Monaco Editor for configuration editing
- **Forms**: React Hook Form with Zod validation
- **Routing**: React Router DOM
- **Build Tool**: Vite
- **Testing**: Vitest with React Testing Library

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- Running Rust API Gateway backend

### Installation

1. Install dependencies:
```bash
npm install
```

2. Start the development server:
```bash
npm run dev
```

3. Open your browser to `http://localhost:3000`

### Building for Production

```bash
npm run build
```

The built files will be in the `dist` directory.

### Running Tests

```bash
# Run tests once
npm test

# Run tests in watch mode
npm run test:watch

# Type checking
npm run type-check
```

## Configuration

The dashboard connects to the API Gateway admin endpoints at `/api` (proxied to `http://localhost:8080/admin` in development).

### Environment Variables

Create a `.env` file for custom configuration:

```env
VITE_API_BASE_URL=http://your-gateway-host:8080
```

## API Integration

The dashboard integrates with the following API Gateway admin endpoints:

- **System**: `/admin/system/status`, `/admin/system/diagnostics`
- **Services**: `/admin/services/*`
- **Configuration**: `/admin/config/*`
- **Metrics**: `/admin/metrics/*`
- **Logs**: `/admin/logs/*`
- **Health**: `/admin/health/*`
- **Audit**: `/admin/audit/*`

## Features in Detail

### Real-time Updates
- Dashboard metrics refresh every 15-30 seconds
- Service health status updates every 30 seconds
- Log streaming with real-time updates
- WebSocket support for live data (when available)

### Responsive Design
- Mobile-first responsive design
- Collapsible sidebar navigation
- Touch-friendly interface
- Optimized for tablets and mobile devices

### Accessibility
- WCAG 2.1 AA compliant
- Keyboard navigation support
- Screen reader friendly
- High contrast mode support

### Security
- JWT token-based authentication
- Role-based access control
- Secure API communication
- Session management

## Development

### Project Structure

```
src/
├── components/          # Reusable UI components
│   ├── ui/             # Basic UI components (Button, Card, Modal)
│   ├── forms/          # Form components
│   └── charts/         # Chart components
├── pages/              # Page components
├── lib/                # Utilities and API client
├── types/              # TypeScript type definitions
└── test/               # Test utilities and setup
```

### Code Style

- TypeScript strict mode enabled
- ESLint with React and TypeScript rules
- Prettier for code formatting
- Conventional commit messages

### Testing Strategy

- Unit tests for components and utilities
- Integration tests for page components
- Mock API responses for consistent testing
- Visual regression testing (planned)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run the test suite
5. Submit a pull request

## Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Performance

- Code splitting for optimal loading
- Lazy loading of heavy components
- Optimized bundle size
- Service worker for caching (planned)

## Deployment

The dashboard can be deployed as static files to any web server:

- Nginx
- Apache
- AWS S3 + CloudFront
- Vercel
- Netlify

Example Nginx configuration:

```nginx
server {
    listen 80;
    server_name admin.your-domain.com;
    root /path/to/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://your-gateway-host:8080/admin;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## License

This project is part of the Rust API Gateway and follows the same license terms.