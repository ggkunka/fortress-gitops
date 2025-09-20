import React, { useState, useEffect, useMemo } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  IconButton,
  Tooltip,
  Chip,
  Avatar,
  LinearProgress,
  Alert,
  Fade,
  Zoom,
  useTheme,
  alpha,
  Button,
  Menu,
  MenuItem,
  Switch,
  FormControlLabel,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Shield as ShieldIcon,
  BugReport as BugIcon,
  Speed as SpeedIcon,
  Visibility as VisibilityIcon,
  Settings as SettingsIcon,
  Refresh as RefreshIcon,
  Fullscreen as FullscreenIcon,
  FilterList as FilterIcon,
  Timeline as TimelineIcon,
  AccountTree as GraphIcon,
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import { useQuery } from 'react-query';
import { Line, Bar, Doughnut, Radar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  RadialLinearScale,
  Title,
  Tooltip as ChartTooltip,
  Legend,
  Filler,
} from 'chart.js';
import { SecurityMetrics, SecurityEvent, UserRole, RolePermissions } from '../types/security';
import { useAuth } from '../contexts/AuthContext';
import SecurityGraph from './SecurityGraph';
import ThreatIntelligenceWidget from './ThreatIntelligenceWidget';
import ComplianceWidget from './ComplianceWidget';
import PatchManagementWidget from './PatchManagementWidget';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  RadialLinearScale,
  Title,
  ChartTooltip,
  Legend,
  Filler
);

interface SecurityDashboardProps {
  userRole: UserRole;
  permissions: RolePermissions;
}

const SecurityDashboard: React.FC<SecurityDashboardProps> = ({ userRole, permissions }) => {
  const theme = useTheme();
  const { user } = useAuth();
  const [refreshInterval, setRefreshInterval] = useState(30000); // 30 seconds
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [selectedTimeRange, setSelectedTimeRange] = useState('24h');
  const [dashboardView, setDashboardView] = useState<'overview' | 'detailed' | 'graph'>('overview');

  // Fetch security metrics
  const { data: securityMetrics, isLoading: metricsLoading } = useQuery<SecurityMetrics>(
    ['security-metrics', selectedTimeRange],
    () => fetchSecurityMetrics(selectedTimeRange),
    {
      refetchInterval: autoRefresh ? refreshInterval : false,
      refetchIntervalInBackground: true,
    }
  );

  // Fetch security events
  const { data: securityEvents = [], isLoading: eventsLoading } = useQuery<SecurityEvent[]>(
    ['security-events', selectedTimeRange],
    () => fetchSecurityEvents(selectedTimeRange),
    {
      refetchInterval: autoRefresh ? refreshInterval : false,
    }
  );

  // Mock data fetchers (replace with actual API calls)
  const fetchSecurityMetrics = async (timeRange: string): Promise<SecurityMetrics> => {
    // Simulate API call
    return {
      timestamp: new Date(),
      totalClusters: 12,
      healthyClusters: 10,
      totalVulnerabilities: 247,
      criticalVulnerabilities: 8,
      highVulnerabilities: 23,
      mediumVulnerabilities: 89,
      lowVulnerabilities: 127,
      patchedVulnerabilities: 156,
      newVulnerabilities: 12,
      riskScore: 72,
      complianceScore: 85,
      securityPosture: 'good',
    };
  };

  const fetchSecurityEvents = async (timeRange: string): Promise<SecurityEvent[]> => {
    // Simulate API call
    return [
      {
        id: '1',
        timestamp: new Date(Date.now() - 1000 * 60 * 15), // 15 minutes ago
        type: 'vulnerability_detected',
        severity: 'critical',
        title: 'Critical CVE-2024-1234 Detected',
        description: 'Remote code execution vulnerability in nginx container',
        source: { type: 'container', id: 'nginx-123', name: 'nginx-web-server' },
        affectedResources: [
          { type: 'pod', id: 'web-pod-1', name: 'web-frontend' },
          { type: 'pod', id: 'web-pod-2', name: 'web-frontend' },
        ],
        recommendations: ['Update nginx to version 1.21.6', 'Apply security patch immediately'],
        status: 'open',
        tags: ['rce', 'nginx', 'critical'],
        metadata: { cvssScore: 9.8, exploitAvailable: true },
      },
      // Add more mock events...
    ];
  };

  // Security posture color mapping
  const getPostureColor = (posture: string) => {
    switch (posture) {
      case 'excellent': return theme.palette.success.main;
      case 'good': return theme.palette.info.main;
      case 'fair': return theme.palette.warning.main;
      case 'poor': return theme.palette.error.main;
      case 'critical': return theme.palette.error.dark;
      default: return theme.palette.grey[500];
    }
  };

  // Risk score color
  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return theme.palette.error.main;
    if (score >= 60) return theme.palette.warning.main;
    if (score >= 40) return theme.palette.info.main;
    return theme.palette.success.main;
  };

  // Chart configurations
  const vulnerabilityTrendData = {
    labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
    datasets: [
      {
        label: 'Critical',
        data: [12, 8, 15, 10, 8, 8],
        borderColor: theme.palette.error.main,
        backgroundColor: alpha(theme.palette.error.main, 0.1),
        fill: true,
        tension: 0.4,
      },
      {
        label: 'High',
        data: [28, 25, 30, 27, 25, 23],
        borderColor: theme.palette.warning.main,
        backgroundColor: alpha(theme.palette.warning.main, 0.1),
        fill: true,
        tension: 0.4,
      },
      {
        label: 'Medium',
        data: [95, 89, 102, 94, 91, 89],
        borderColor: theme.palette.info.main,
        backgroundColor: alpha(theme.palette.info.main, 0.1),
        fill: true,
        tension: 0.4,
      },
    ],
  };

  const severityDistributionData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [
      {
        data: [
          securityMetrics?.criticalVulnerabilities || 0,
          securityMetrics?.highVulnerabilities || 0,
          securityMetrics?.mediumVulnerabilities || 0,
          securityMetrics?.lowVulnerabilities || 0,
        ],
        backgroundColor: [
          theme.palette.error.main,
          theme.palette.warning.main,
          theme.palette.info.main,
          theme.palette.success.main,
        ],
        borderWidth: 0,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom' as const,
        labels: {
          usePointStyle: true,
          padding: 20,
          color: theme.palette.text.primary,
        },
      },
      tooltip: {
        backgroundColor: alpha(theme.palette.background.paper, 0.95),
        titleColor: theme.palette.text.primary,
        bodyColor: theme.palette.text.secondary,
        borderColor: theme.palette.divider,
        borderWidth: 1,
      },
    },
    scales: {
      x: {
        grid: {
          color: alpha(theme.palette.divider, 0.1),
        },
        ticks: {
          color: theme.palette.text.secondary,
        },
      },
      y: {
        grid: {
          color: alpha(theme.palette.divider, 0.1),
        },
        ticks: {
          color: theme.palette.text.secondary,
        },
      },
    },
  };

  if (metricsLoading) {
    return (
      <Box sx={{ width: '100%', mt: 2 }}>
        <LinearProgress />
        <Typography variant="h6" sx={{ mt: 2, textAlign: 'center' }}>
          Loading security dashboard...
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3, minHeight: '100vh', bgcolor: 'background.default' }}>
      {/* Dashboard Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
          <Box>
            <Typography variant="h3" component="h1" sx={{ fontWeight: 700, mb: 1 }}>
              Security Command Center
            </Typography>
            <Typography variant="subtitle1" color="text.secondary">
              Real-time security monitoring and threat intelligence
            </Typography>
          </Box>
          
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <FormControlLabel
              control={
                <Switch
                  checked={autoRefresh}
                  onChange={(e) => setAutoRefresh(e.target.checked)}
                  color="primary"
                />
              }
              label="Auto Refresh"
            />
            
            <Tooltip title="Refresh Dashboard">
              <IconButton onClick={() => window.location.reload()}>
                <RefreshIcon />
              </IconButton>
            </Tooltip>
            
            {permissions.permissions.dashboard.customize && (
              <Tooltip title="Dashboard Settings">
                <IconButton>
                  <SettingsIcon />
                </IconButton>
              </Tooltip>
            )}
          </Box>
        </Box>
      </motion.div>

      {/* Security Overview Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <Card
              sx={{
                background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.primary.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
                height: '100%',
              }}
            >
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" gutterBottom variant="body2">
                      Security Posture
                    </Typography>
                    <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
                      {securityMetrics?.securityPosture?.toUpperCase()}
                    </Typography>
                    <Chip
                      label={`Risk Score: ${securityMetrics?.riskScore}/100`}
                      size="small"
                      sx={{
                        bgcolor: alpha(getRiskScoreColor(securityMetrics?.riskScore || 0), 0.2),
                        color: getRiskScoreColor(securityMetrics?.riskScore || 0),
                      }}
                    />
                  </Box>
                  <Avatar
                    sx={{
                      bgcolor: getPostureColor(securityMetrics?.securityPosture || 'fair'),
                      width: 56,
                      height: 56,
                    }}
                  >
                    <ShieldIcon sx={{ fontSize: 32 }} />
                  </Avatar>
                </Box>
              </CardContent>
            </Card>
          </motion.div>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            <Card
              sx={{
                background: `linear-gradient(135deg, ${alpha(theme.palette.error.main, 0.1)} 0%, ${alpha(theme.palette.error.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`,
                height: '100%',
              }}
            >
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" gutterBottom variant="body2">
                      Critical Vulnerabilities
                    </Typography>
                    <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
                      {securityMetrics?.criticalVulnerabilities}
                    </Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <TrendingUpIcon sx={{ fontSize: 16, color: 'error.main', mr: 0.5 }} />
                      <Typography variant="caption" color="error.main">
                        +{securityMetrics?.newVulnerabilities} new
                      </Typography>
                    </Box>
                  </Box>
                  <Avatar
                    sx={{
                      bgcolor: theme.palette.error.main,
                      width: 56,
                      height: 56,
                    }}
                  >
                    <BugIcon sx={{ fontSize: 32 }} />
                  </Avatar>
                </Box>
              </CardContent>
            </Card>
          </motion.div>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.3 }}
          >
            <Card
              sx={{
                background: `linear-gradient(135deg, ${alpha(theme.palette.success.main, 0.1)} 0%, ${alpha(theme.palette.success.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.success.main, 0.2)}`,
                height: '100%',
              }}
            >
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" gutterBottom variant="body2">
                      Healthy Clusters
                    </Typography>
                    <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
                      {securityMetrics?.healthyClusters}/{securityMetrics?.totalClusters}
                    </Typography>
                    <LinearProgress
                      variant="determinate"
                      value={(securityMetrics?.healthyClusters || 0) / (securityMetrics?.totalClusters || 1) * 100}
                      sx={{
                        height: 6,
                        borderRadius: 3,
                        bgcolor: alpha(theme.palette.success.main, 0.2),
                        '& .MuiLinearProgress-bar': {
                          bgcolor: theme.palette.success.main,
                        },
                      }}
                    />
                  </Box>
                  <Avatar
                    sx={{
                      bgcolor: theme.palette.success.main,
                      width: 56,
                      height: 56,
                    }}
                  >
                    <CheckCircleIcon sx={{ fontSize: 32 }} />
                  </Avatar>
                </Box>
              </CardContent>
            </Card>
          </motion.div>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.4 }}
          >
            <Card
              sx={{
                background: `linear-gradient(135deg, ${alpha(theme.palette.info.main, 0.1)} 0%, ${alpha(theme.palette.info.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.info.main, 0.2)}`,
                height: '100%',
              }}
            >
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography color="text.secondary" gutterBottom variant="body2">
                      Compliance Score
                    </Typography>
                    <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
                      {securityMetrics?.complianceScore}%
                    </Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <TrendingUpIcon sx={{ fontSize: 16, color: 'success.main', mr: 0.5 }} />
                      <Typography variant="caption" color="success.main">
                        +5% this month
                      </Typography>
                    </Box>
                  </Box>
                  <Avatar
                    sx={{
                      bgcolor: theme.palette.info.main,
                      width: 56,
                      height: 56,
                    }}
                  >
                    <SpeedIcon sx={{ fontSize: 32 }} />
                  </Avatar>
                </Box>
              </CardContent>
            </Card>
          </motion.div>
        </Grid>
      </Grid>

      {/* Main Dashboard Content */}
      <Grid container spacing={3}>
        {/* Vulnerability Trends Chart */}
        <Grid item xs={12} lg={8}>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.5 }}
          >
            <Card sx={{ height: 400 }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600 }}>
                    Vulnerability Trends
                  </Typography>
                  <Box>
                    <Button size="small" startIcon={<TimelineIcon />}>
                      View Details
                    </Button>
                  </Box>
                </Box>
                <Box sx={{ height: 300 }}>
                  <Line data={vulnerabilityTrendData} options={chartOptions} />
                </Box>
              </CardContent>
            </Card>
          </motion.div>
        </Grid>

        {/* Severity Distribution */}
        <Grid item xs={12} lg={4}>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.6 }}
          >
            <Card sx={{ height: 400 }}>
              <CardContent>
                <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
                  Severity Distribution
                </Typography>
                <Box sx={{ height: 300 }}>
                  <Doughnut
                    data={severityDistributionData}
                    options={{
                      ...chartOptions,
                      plugins: {
                        ...chartOptions.plugins,
                        legend: {
                          position: 'bottom',
                          labels: {
                            usePointStyle: true,
                            padding: 15,
                          },
                        },
                      },
                    }}
                  />
                </Box>
              </CardContent>
            </Card>
          </motion.div>
        </Grid>

        {/* Security Events Feed */}
        <Grid item xs={12} lg={6}>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.7 }}
          >
            <Card sx={{ height: 500 }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600 }}>
                    Recent Security Events
                  </Typography>
                  <IconButton size="small">
                    <FilterIcon />
                  </IconButton>
                </Box>
                <Box sx={{ maxHeight: 400, overflow: 'auto' }}>
                  <AnimatePresence>
                    {securityEvents.map((event, index) => (
                      <motion.div
                        key={event.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: 20 }}
                        transition={{ duration: 0.3, delay: index * 0.1 }}
                      >
                        <Alert
                          severity={event.severity === 'critical' ? 'error' : event.severity as any}
                          sx={{ mb: 2 }}
                          action={
                            permissions.permissions.vulnerabilities.view && (
                              <Button size="small" startIcon={<VisibilityIcon />}>
                                View
                              </Button>
                            )
                          }
                        >
                          <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                            {event.title}
                          </Typography>
                          <Typography variant="body2" sx={{ mt: 0.5 }}>
                            {event.description}
                          </Typography>
                          <Box sx={{ mt: 1, display: 'flex', gap: 1 }}>
                            {event.tags.map((tag) => (
                              <Chip key={tag} label={tag} size="small" variant="outlined" />
                            ))}
                          </Box>
                        </Alert>
                      </motion.div>
                    ))}
                  </AnimatePresence>
                </Box>
              </CardContent>
            </Card>
          </motion.div>
        </Grid>

        {/* Security Graph Visualization */}
        <Grid item xs={12} lg={6}>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.8 }}
          >
            <Card sx={{ height: 500 }}>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 600 }}>
                    Security Relationship Graph
                  </Typography>
                  <Button size="small" startIcon={<GraphIcon />}>
                    Full View
                  </Button>
                </Box>
                <Box sx={{ height: 400 }}>
                  <SecurityGraph height={400} />
                </Box>
              </CardContent>
            </Card>
          </motion.div>
        </Grid>

        {/* Additional Widgets for Admin Users */}
        {permissions.permissions.system.configure && (
          <>
            <Grid item xs={12} lg={4}>
              <ThreatIntelligenceWidget />
            </Grid>
            <Grid item xs={12} lg={4}>
              <ComplianceWidget />
            </Grid>
            <Grid item xs={12} lg={4}>
              <PatchManagementWidget />
            </Grid>
          </>
        )}
      </Grid>
    </Box>
  );
};

export default SecurityDashboard;
