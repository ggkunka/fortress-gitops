# MCP Security Platform - Web UI

Modern React-based web interface for the MCP Security Assessment Platform.

## Features

- **Modern UI/UX**: Clean, responsive design built with Material-UI
- **Real-time Updates**: Live data updates using React Query
- **Security Dashboard**: Comprehensive security metrics and visualizations
- **Scan Management**: Create, monitor, and manage security scans
- **Vulnerability Tracking**: Detailed vulnerability analysis and remediation
- **Report Generation**: Interactive reports with multiple export formats
- **Integration Management**: Configure external system integrations
- **Plugin Marketplace**: Discover and install security plugins
- **Role-based Access**: Granular permissions and access control

## Technology Stack

- **React 18** - Modern React with hooks and concurrent features
- **TypeScript** - Type-safe JavaScript development
- **Material-UI (MUI)** - Google's Material Design components
- **React Query** - Data fetching and caching
- **React Router** - Client-side routing
- **React Hook Form** - Efficient form handling
- **Axios** - HTTP client for API calls
- **Recharts** - Data visualization and charting

## Getting Started

### Prerequisites

- Node.js 16+ and npm
- Access to MCP Security Platform API

### Installation

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Configure environment**:
   ```bash
   cp .env.example .env.local
   ```
   
   Update `.env.local` with your API configuration:
   ```
   REACT_APP_API_URL=http://localhost:8000/v1
   REACT_APP_WEBSOCKET_URL=ws://localhost:8000/ws
   ```

3. **Start development server**:
   ```bash
   npm start
   ```

4. **Access the application**:
   Open [http://localhost:3000](http://localhost:3000)

### Demo Credentials

- **Username**: `admin`
- **Password**: `admin123`

## Development

### Available Scripts

- `npm start` - Start development server with hot reload
- `npm build` - Build production-ready application
- `npm test` - Run test suite
- `npm run lint` - Run ESLint for code quality
- `npm run format` - Format code with Prettier
- `npm run analyze` - Analyze bundle size

### Project Structure

```
src/
├── components/          # Reusable UI components
│   ├── common/         # Generic components (buttons, cards, etc.)
│   ├── forms/          # Form components
│   ├── layout/         # Layout components (header, sidebar, etc.)
│   └── charts/         # Data visualization components
├── contexts/           # React contexts (auth, notifications, etc.)
├── hooks/              # Custom React hooks
├── pages/              # Page components
│   ├── auth/          # Authentication pages
│   ├── dashboard/     # Dashboard and overview
│   ├── scans/         # Scan management
│   ├── vulnerabilities/ # Vulnerability management
│   ├── reports/       # Report generation and viewing
│   ├── integrations/  # External integrations
│   ├── marketplace/   # Plugin marketplace
│   └── settings/      # Application settings
├── services/          # API service clients
├── types/             # TypeScript type definitions
├── utils/             # Utility functions
└── App.tsx            # Main application component
```

### Key Components

#### Authentication
- JWT-based authentication with automatic token refresh
- Role-based access control with permission checking
- Secure logout with token cleanup

#### Dashboard
- Real-time security metrics and KPIs
- Interactive charts showing vulnerability trends
- Recent scan activity and status updates
- Quick access to critical security issues

#### Scan Management
- Create and configure security scans
- Monitor scan progress with real-time updates
- View detailed scan results and findings
- Schedule recurring scans

#### Vulnerability Management
- Comprehensive vulnerability database
- Advanced filtering and search capabilities
- Vulnerability details with remediation guidance
- Risk scoring and prioritization

#### Report Generation
- Multiple report types (security, compliance, executive)
- Interactive report builder with filters
- Export to PDF, HTML, CSV, and Excel formats
- Scheduled report generation and distribution

#### Integration Management
- Configure SIEM, cloud, and threat intelligence integrations
- Test connection and monitor integration health
- Manage authentication credentials securely
- Integration templates and marketplace

#### Plugin Marketplace
- Discover and install security plugins
- Plugin ratings, reviews, and documentation
- Dependency management and compatibility checking
- Community contributions and official plugins

### State Management

The application uses a combination of:
- **React Query** for server state management and caching
- **React Context** for global application state (auth, notifications)
- **Local Component State** for UI-specific state

### API Integration

- **RESTful API** communication using Axios
- **WebSocket** connections for real-time updates
- **JWT Authentication** with automatic token refresh
- **Error Handling** with user-friendly error messages
- **Request/Response Interceptors** for logging and debugging

### Styling and Theming

- **Material-UI Theme** with custom color palette
- **Responsive Design** with mobile-first approach
- **Dark Mode Support** (planned feature)
- **CSS-in-JS** with emotion styling engine
- **Custom Components** following Material Design principles

## Production Build

### Building for Production

```bash
npm run build
```

This creates an optimized production build in the `build` folder.

### Deployment Options

#### Static Hosting (Recommended)
- **Netlify**: Connect GitHub repo for automatic deployments
- **Vercel**: Zero-config deployments with preview environments
- **AWS S3 + CloudFront**: Scalable static hosting with CDN
- **Azure Static Web Apps**: Integrated with Azure services

#### Container Deployment
```dockerfile
FROM node:16-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

### Environment Configuration

Production environment variables:
```bash
REACT_APP_API_URL=https://api.yourdomain.com/v1
REACT_APP_WEBSOCKET_URL=wss://api.yourdomain.com/ws
REACT_APP_SENTRY_DSN=your-sentry-dsn
REACT_APP_ANALYTICS_ID=your-analytics-id
```

## Security Features

- **Content Security Policy** headers
- **HTTPS enforcement** in production
- **XSS protection** with input sanitization
- **CSRF protection** for state-changing operations
- **Secure token storage** with automatic cleanup
- **Permission-based UI rendering**

## Performance Optimization

- **Code Splitting** with React.lazy and Suspense
- **Bundle Analysis** with webpack-bundle-analyzer
- **Image Optimization** with lazy loading
- **API Response Caching** with React Query
- **Memoization** of expensive computations
- **Virtual Scrolling** for large data sets

## Testing

### Test Structure
```
src/
├── __tests__/          # Test files
├── components/
│   └── __tests__/      # Component tests
└── utils/
    └── __tests__/      # Utility tests
```

### Running Tests
```bash
npm test                # Run all tests
npm test -- --watch    # Run tests in watch mode
npm test -- --coverage # Run tests with coverage report
```

## Browser Support

- **Chrome** 90+
- **Firefox** 88+
- **Safari** 14+
- **Edge** 90+

## Contributing

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-feature`
3. **Make your changes** with proper testing
4. **Run linting and tests**: `npm run lint && npm test`
5. **Commit your changes**: `git commit -m 'Add new feature'`
6. **Push to the branch**: `git push origin feature/new-feature`
7. **Open a pull request**

### Code Style

- Follow **TypeScript best practices**
- Use **functional components** with hooks
- Implement **proper error boundaries**
- Add **comprehensive prop types**
- Write **meaningful test cases**
- Follow **Material-UI patterns**

## Troubleshooting

### Common Issues

1. **API Connection Errors**
   - Verify `REACT_APP_API_URL` is correct
   - Check CORS configuration on API server
   - Ensure API server is running and accessible

2. **Authentication Issues**
   - Clear browser localStorage and cookies
   - Check JWT token expiration
   - Verify API authentication endpoints

3. **Build Failures**
   - Clear node_modules and reinstall: `rm -rf node_modules && npm install`
   - Check Node.js version compatibility
   - Verify environment variables are set

### Getting Help

- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Check API documentation
- **Community**: Join our Slack channel for support

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.