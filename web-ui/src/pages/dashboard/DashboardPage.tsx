import React from 'react';
import {
  Grid,
  Card,
  CardContent,
  Typography,
  Box,
  Chip,
  LinearProgress,
  CircularProgress,
  Alert,
} from '@mui/material';
import {
  Security as SecurityIcon,
  BugReport as VulnerabilityIcon,
  Assessment as ReportsIcon,
  Cloud as IntegrationsIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
} from '@mui/icons-material';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { useQuery } from '@tanstack/react-query';
import { dashboardApi } from '../../services/dashboardApi';

const COLORS = ['#f44336', '#ff9800', '#ffc107', '#4caf50', '#2196f3'];

interface MetricCardProps {
  title: string;
  value: string | number;
  change?: number;
  icon: React.ReactElement;
  color?: string;
  loading?: boolean;
}

const MetricCard: React.FC<MetricCardProps> = ({
  title,
  value,
  change,
  icon,
  color = 'primary.main',
  loading = false,
}) => {
  return (
    <Card>
      <CardContent>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Box>
            <Typography color="textSecondary" gutterBottom variant="body2">
              {title}
            </Typography>
            <Typography variant="h4" component="div">
              {loading ? '-' : value}
            </Typography>
          </Box>
          <Box sx={{ color, opacity: 0.8 }}>
            {icon}
          </Box>
        </Box>
        {change !== undefined && (
          <Box display="flex" alignItems="center" mt={1}>
            {change > 0 ? (
              <TrendingUpIcon sx={{ color: 'error.main', mr: 0.5 }} fontSize="small" />
            ) : (
              <TrendingDownIcon sx={{ color: 'success.main', mr: 0.5 }} fontSize="small" />
            )}
            <Typography
              variant="body2"
              sx={{
                color: change > 0 ? 'error.main' : 'success.main',
              }}
            >
              {Math.abs(change)}% from last week
            </Typography>
          </Box>
        )}
        {loading && <LinearProgress sx={{ mt: 1 }} />}
      </CardContent>
    </Card>
  );
};

export const DashboardPage: React.FC = () => {
  // Dashboard statistics
  const { data: dashboardStats, isLoading: statsLoading, error: statsError } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: () => dashboardApi.getDashboardStats(),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  // Vulnerability trends
  const { data: vulnerabilityTrends, isLoading: trendsLoading } = useQuery({
    queryKey: ['vulnerability-trends'],
    queryFn: () => dashboardApi.getVulnerabilityTrends('30d'),
    refetchInterval: 60000, // Refresh every minute
  });

  // Recent scans
  const { data: recentScans, isLoading: scansLoading } = useQuery({
    queryKey: ['recent-scans'],
    queryFn: () => dashboardApi.getRecentScans(5),
    refetchInterval: 10000, // Refresh every 10 seconds
  });

  // Top vulnerabilities
  const { data: topVulnerabilities, isLoading: topVulnLoading } = useQuery({
    queryKey: ['top-vulnerabilities'],
    queryFn: () => dashboardApi.getTopVulnerabilities(5),
    refetchInterval: 60000,
  });

  // Vulnerability distribution
  const { data: vulnDistribution, isLoading: distributionLoading } = useQuery({
    queryKey: ['vulnerability-distribution'],
    queryFn: () => dashboardApi.getVulnerabilityDistribution(),
    refetchInterval: 60000,
  });

  if (statsError) {
    return (
      <Alert severity="error" sx={{ m: 2 }}>
        Failed to load dashboard data. Please check your connection and try again.
      </Alert>
    );
  }

  // Prepare chart data
  const pieChartData = vulnDistribution ? [
    { name: 'Critical', value: vulnDistribution.critical, color: '#f44336' },
    { name: 'High', value: vulnDistribution.high, color: '#ff9800' },
    { name: 'Medium', value: vulnDistribution.medium, color: '#ffc107' },
    { name: 'Low', value: vulnDistribution.low, color: '#4caf50' },
    { name: 'Info', value: vulnDistribution.info, color: '#2196f3' },
  ].filter(item => item.value > 0) : [];

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'primary';
      case 'completed': return 'success';
      case 'failed': return 'error';
      case 'pending': return 'warning';
      default: return 'default';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#f44336';
      case 'high': return '#ff9800';
      case 'medium': return '#ffc107';
      case 'low': return '#4caf50';
      case 'info': return '#2196f3';
      default: return '#666';
    }
  };

  return (
    <Box>
      {/* Header */}
      <Typography variant="h4" component="h1" gutterBottom>
        Security Dashboard
      </Typography>

      {/* Key Metrics */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Total Scans"
            value={dashboardStats?.total_scans || 0}
            icon={<SecurityIcon fontSize="large" />}
            loading={statsLoading}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Critical Vulnerabilities"
            value={dashboardStats?.critical_vulnerabilities || 0}
            icon={<VulnerabilityIcon fontSize="large" />}
            color="error.main"
            loading={statsLoading}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Protected Assets"
            value={`${dashboardStats?.protected_assets || 0}/${dashboardStats?.total_assets || 0}`}
            icon={<ReportsIcon fontSize="large" />}
            color="success.main"
            loading={statsLoading}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <MetricCard
            title="Active Integrations"
            value={`${dashboardStats?.active_integrations || 0}/${dashboardStats?.total_integrations || 0}`}
            icon={<IntegrationsIcon fontSize="large" />}
            color="info.main"
            loading={statsLoading}
          />
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        {/* Vulnerability Trends Chart */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Vulnerability Trends (30 Days)
              </Typography>
              {trendsLoading ? (
                <Box display="flex" justifyContent="center" py={4}>
                  <CircularProgress />
                </Box>
              ) : vulnerabilityTrends && vulnerabilityTrends.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <LineChart data={vulnerabilityTrends}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" />
                    <YAxis />
                    <Tooltip />
                    <Line
                      type="monotone"
                      dataKey="critical"
                      stroke="#f44336"
                      strokeWidth={2}
                      name="Critical"
                    />
                    <Line
                      type="monotone"
                      dataKey="high"
                      stroke="#ff9800"
                      strokeWidth={2}
                      name="High"
                    />
                    <Line
                      type="monotone"
                      dataKey="medium"
                      stroke="#ffc107"
                      strokeWidth={2}
                      name="Medium"
                    />
                    <Line
                      type="monotone"
                      dataKey="low"
                      stroke="#4caf50"
                      strokeWidth={2}
                      name="Low"
                    />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <Typography variant="body2" color="textSecondary" textAlign="center" py={4}>
                  No vulnerability trend data available
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Vulnerability Distribution */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Vulnerability Distribution
              </Typography>
              {distributionLoading ? (
                <Box display="flex" justifyContent="center" py={4}>
                  <CircularProgress />
                </Box>
              ) : pieChartData.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={pieChartData}
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, value }) => `${name}: ${value}`}
                    >
                      {pieChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <Typography variant="body2" color="textSecondary" textAlign="center" py={4}>
                  No vulnerability data available
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Scans */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Recent Scans
              </Typography>
              {scansLoading ? (
                <Box display="flex" justifyContent="center" py={2}>
                  <CircularProgress size={24} />
                </Box>
              ) : recentScans && recentScans.length > 0 ? (
                <Box>
                  {recentScans.map((scan) => (
                    <Card key={scan.id} variant="outlined" sx={{ mb: 1 }}>
                      <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
                        <Box display="flex" alignItems="center" justifyContent="space-between">
                          <Box>
                            <Typography variant="subtitle2" component="div">
                              {scan.name}
                            </Typography>
                            <Typography variant="body2" color="textSecondary">
                              {scan.target} • {new Date(scan.started_at).toLocaleString()}
                            </Typography>
                          </Box>
                          <Box display="flex" alignItems="center" gap={1}>
                            <Typography variant="body2" color="error.main">
                              {scan.vulnerabilities_found} issues
                            </Typography>
                            <Chip
                              label={scan.status}
                              size="small"
                              color={getStatusColor(scan.status) as any}
                              variant="outlined"
                            />
                          </Box>
                        </Box>
                        {scan.status === 'running' && (
                          <Box mt={1}>
                            <LinearProgress variant="determinate" value={scan.progress} />
                            <Typography variant="caption" color="textSecondary">
                              {scan.progress}% complete
                            </Typography>
                          </Box>
                        )}
                      </CardContent>
                    </Card>
                  ))}
                </Box>
              ) : (
                <Typography variant="body2" color="textSecondary" textAlign="center" py={2}>
                  No recent scans available
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Top Vulnerabilities */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Top Vulnerabilities
              </Typography>
              {topVulnLoading ? (
                <Box display="flex" justifyContent="center" py={2}>
                  <CircularProgress size={24} />
                </Box>
              ) : topVulnerabilities && topVulnerabilities.length > 0 ? (
                <Box>
                  {topVulnerabilities.map((vuln) => (
                    <Card key={vuln.id} variant="outlined" sx={{ mb: 1 }}>
                      <CardContent sx={{ py: 2, '&:last-child': { pb: 2 } }}>
                        <Box display="flex" alignItems="center" justifyContent="space-between">
                          <Box flexGrow={1}>
                            <Typography variant="subtitle2" component="div" noWrap>
                              {vuln.title}
                            </Typography>
                            <Typography variant="body2" color="textSecondary">
                              {vuln.affected_assets} assets affected • CVSS {vuln.cvss_score}
                            </Typography>
                          </Box>
                          <Chip
                            label={vuln.severity.toUpperCase()}
                            size="small"
                            sx={{
                              backgroundColor: getSeverityColor(vuln.severity),
                              color: 'white',
                              fontWeight: 'bold',
                            }}
                          />
                        </Box>
                      </CardContent>
                    </Card>
                  ))}
                </Box>
              ) : (
                <Typography variant="body2" color="textSecondary" textAlign="center" py={2}>
                  No vulnerability data available
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};