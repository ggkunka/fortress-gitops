import React, { useState } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Grid,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Button,
  IconButton,
  Tooltip,
  Avatar,
  LinearProgress,
  Tab,
  Tabs,
  useTheme,
  alpha,
} from '@mui/material';
import {
  AccountTree as WorkloadIcon,
  CloudQueue as ContainerIcon,
  Storage as PodIcon,
  Security as SecurityIcon,
  Shield as ProtectionIcon,
  Warning as WarningIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Visibility as ViewIcon,
  Block as BlockIcon,
  PlayArrow as StartIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';

const WorkloadProtection: React.FC = () => {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);

  const workloadData = {
    summary: {
      totalWorkloads: 1456,
      protectedWorkloads: 1398,
      vulnerableWorkloads: 58,
      clusters: 24,
      namespaces: 89,
      pods: 8934,
      containers: 12567
    },
    protectionStatus: {
      runtime: 96,
      network: 94,
      storage: 92,
      compliance: 89
    },
    clusters: [
      {
        id: 'prod-east-1',
        name: 'Production East',
        provider: 'AWS',
        status: 'healthy',
        nodes: 12,
        pods: 2456,
        protection: 98,
        threats: 2,
        vulnerabilities: 5,
        lastScan: '2 hours ago'
      },
      {
        id: 'prod-west-1',
        name: 'Production West',
        provider: 'AWS',
        status: 'healthy',
        nodes: 8,
        pods: 1789,
        protection: 97,
        threats: 1,
        vulnerabilities: 3,
        lastScan: '1 hour ago'
      },
      {
        id: 'staging-central',
        name: 'Staging Central',
        provider: 'Azure',
        status: 'warning',
        nodes: 6,
        pods: 1234,
        protection: 89,
        threats: 5,
        vulnerabilities: 12,
        lastScan: '4 hours ago'
      },
      {
        id: 'dev-cluster',
        name: 'Development',
        provider: 'GCP',
        status: 'healthy',
        nodes: 4,
        pods: 567,
        protection: 85,
        threats: 0,
        vulnerabilities: 8,
        lastScan: '30 minutes ago'
      }
    ],
    workloads: [
      {
        id: 'web-app-prod',
        name: 'Web Application',
        namespace: 'production',
        cluster: 'prod-east-1',
        replicas: 6,
        status: 'running',
        protection: 'enabled',
        riskLevel: 'low',
        lastActivity: '2 minutes ago',
        threats: 0,
        vulnerabilities: 2
      },
      {
        id: 'api-service',
        name: 'API Service',
        namespace: 'production',
        cluster: 'prod-east-1',
        replicas: 4,
        status: 'running',
        protection: 'enabled',
        riskLevel: 'medium',
        lastActivity: '5 minutes ago',
        threats: 1,
        vulnerabilities: 4
      },
      {
        id: 'database-worker',
        name: 'Database Worker',
        namespace: 'database',
        cluster: 'prod-west-1',
        replicas: 2,
        status: 'running',
        protection: 'enabled',
        riskLevel: 'high',
        lastActivity: '1 minute ago',
        threats: 2,
        vulnerabilities: 7
      },
      {
        id: 'cache-service',
        name: 'Cache Service',
        namespace: 'production',
        cluster: 'prod-east-1',
        replicas: 3,
        status: 'running',
        protection: 'disabled',
        riskLevel: 'critical',
        lastActivity: '10 minutes ago',
        threats: 3,
        vulnerabilities: 12
      }
    ]
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy': return '#10b981';
      case 'warning': return '#eab308';
      case 'critical': return '#ef4444';
      case 'running': return '#10b981';
      case 'stopped': return '#6b7280';
      default: return '#6b7280';
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'low': return '#10b981';
      case 'medium': return '#eab308';
      case 'high': return '#f97316';
      case 'critical': return '#ef4444';
      default: return '#6b7280';
    }
  };

  const getProtectionColor = (protection: string) => {
    switch (protection) {
      case 'enabled': return '#10b981';
      case 'disabled': return '#ef4444';
      case 'partial': return '#eab308';
      default: return '#6b7280';
    }
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <Card sx={{ 
        background: 'linear-gradient(135deg, #1e293b, #334155)', 
        border: '1px solid rgba(255,255,255,0.1)'
      }}>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 3, display: 'flex', alignItems: 'center' }}>
            <WorkloadIcon sx={{ mr: 1, color: '#8b5cf6' }} />
            Workload Protection
          </Typography>

          {/* Summary Cards */}
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ 
                textAlign: 'center', 
                p: 2, 
                backgroundColor: 'rgba(0,0,0,0.2)', 
                borderRadius: 2 
              }}>
                <Avatar sx={{ 
                  width: 48, 
                  height: 48, 
                  mx: 'auto', 
                  mb: 1, 
                  backgroundColor: '#8b5cf6' 
                }}>
                  <WorkloadIcon />
                </Avatar>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#8b5cf6' }}>
                  {workloadData.summary.totalWorkloads.toLocaleString()}
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                  Total Workloads
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ 
                textAlign: 'center', 
                p: 2, 
                backgroundColor: 'rgba(0,0,0,0.2)', 
                borderRadius: 2 
              }}>
                <Avatar sx={{ 
                  width: 48, 
                  height: 48, 
                  mx: 'auto', 
                  mb: 1, 
                  backgroundColor: '#10b981' 
                }}>
                  <ProtectionIcon />
                </Avatar>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#10b981' }}>
                  {workloadData.summary.protectedWorkloads.toLocaleString()}
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                  Protected
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ 
                textAlign: 'center', 
                p: 2, 
                backgroundColor: 'rgba(0,0,0,0.2)', 
                borderRadius: 2 
              }}>
                <Avatar sx={{ 
                  width: 48, 
                  height: 48, 
                  mx: 'auto', 
                  mb: 1, 
                  backgroundColor: '#3b82f6' 
                }}>
                  <ContainerIcon />
                </Avatar>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#3b82f6' }}>
                  {workloadData.summary.containers.toLocaleString()}
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                  Containers
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ 
                textAlign: 'center', 
                p: 2, 
                backgroundColor: 'rgba(0,0,0,0.2)', 
                borderRadius: 2 
              }}>
                <Avatar sx={{ 
                  width: 48, 
                  height: 48, 
                  mx: 'auto', 
                  mb: 1, 
                  backgroundColor: '#f59e0b' 
                }}>
                  <PodIcon />
                </Avatar>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#f59e0b' }}>
                  {workloadData.summary.pods.toLocaleString()}
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                  Pods
                </Typography>
              </Box>
            </Grid>
          </Grid>

          {/* Protection Status */}
          <Box sx={{ mb: 3 }}>
            <Typography variant="subtitle2" sx={{ mb: 2, color: 'rgba(255,255,255,0.8)' }}>
              Protection Coverage
            </Typography>
            <Grid container spacing={2}>
              {Object.entries(workloadData.protectionStatus).map(([key, value]) => (
                <Grid item xs={12} sm={6} md={3} key={key}>
                  <Box sx={{ 
                    p: 2, 
                    backgroundColor: 'rgba(0,0,0,0.2)', 
                    borderRadius: 2 
                  }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                      <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)', textTransform: 'capitalize' }}>
                        {key}
                      </Typography>
                      <Typography variant="body2" sx={{ color: '#10b981', fontWeight: 600 }}>
                        {value}%
                      </Typography>
                    </Box>
                    <LinearProgress 
                      variant="determinate" 
                      value={value}
                      sx={{ 
                        height: 6, 
                        borderRadius: 3,
                        backgroundColor: 'rgba(255,255,255,0.1)',
                        '& .MuiLinearProgress-bar': {
                          backgroundColor: value > 90 ? '#10b981' : value > 80 ? '#eab308' : '#ef4444',
                          borderRadius: 3
                        }
                      }}
                    />
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Box>

          {/* Tabs */}
          <Box sx={{ borderBottom: 1, borderColor: 'rgba(255,255,255,0.1)', mb: 3 }}>
            <Tabs 
              value={activeTab} 
              onChange={handleTabChange}
              sx={{
                '& .MuiTab-root': {
                  color: 'rgba(255,255,255,0.7)',
                  '&.Mui-selected': {
                    color: '#8b5cf6'
                  }
                },
                '& .MuiTabs-indicator': {
                  backgroundColor: '#8b5cf6'
                }
              }}
            >
              <Tab label="Clusters" />
              <Tab label="Workloads" />
            </Tabs>
          </Box>

          {/* Clusters Tab */}
          {activeTab === 0 && (
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3 }}
            >
              <TableContainer component={Paper} sx={{ 
                backgroundColor: 'rgba(0,0,0,0.2)',
                border: '1px solid rgba(255,255,255,0.1)'
              }}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: 'rgba(255,255,255,0.8)', fontWeight: 600 }}>
                        Cluster
                      </TableCell>
                      <TableCell sx={{ color: 'rgba(255,255,255,0.8)', fontWeight: 600 }}>
                        Status
                      </TableCell>
                      <TableCell sx={{ color: 'rgba(255,255,255,0.8)', fontWeight: 600 }}>
                        Resources
                      </TableCell>
                      <TableCell sx={{ color: 'rgba(255,255,255,0.8)', fontWeight: 600 }}>
                        Protection
                      </TableCell>
                      <TableCell sx={{ color: 'rgba(255,255,255,0.8)', fontWeight: 600 }}>
                        Security
                      </TableCell>
                      <TableCell sx={{ color: 'rgba(255,255,255,0.8)', fontWeight: 600 }}>
                        Actions
                      </TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {workloadData.clusters.map((cluster, index) => (
                      <motion.tr
                        key={cluster.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.3, delay: index * 0.1 }}
                        component={TableRow}
                        sx={{ '&:hover': { backgroundColor: 'rgba(255,255,255,0.05)' } }}
                      >
                        <TableCell sx={{ color: 'white' }}>
                          <Box>
                            <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                              {cluster.name}
                            </Typography>
                            <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.6)' }}>
                              {cluster.provider} • {cluster.id}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={cluster.status}
                            size="small"
                            sx={{ 
                              backgroundColor: alpha(getStatusColor(cluster.status), 0.2),
                              color: getStatusColor(cluster.status),
                              textTransform: 'capitalize'
                            }}
                          />
                        </TableCell>
                        <TableCell sx={{ color: 'white' }}>
                          <Typography variant="body2">
                            {cluster.nodes} nodes • {cluster.pods.toLocaleString()} pods
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center' }}>
                            <Typography variant="body2" sx={{ 
                              color: cluster.protection > 95 ? '#10b981' : '#eab308',
                              fontWeight: 600,
                              mr: 1
                            }}>
                              {cluster.protection}%
                            </Typography>
                            <LinearProgress 
                              variant="determinate" 
                              value={cluster.protection}
                              sx={{ 
                                width: 60,
                                height: 4, 
                                borderRadius: 2,
                                backgroundColor: 'rgba(255,255,255,0.1)',
                                '& .MuiLinearProgress-bar': {
                                  backgroundColor: cluster.protection > 95 ? '#10b981' : '#eab308'
                                }
                              }}
                            />
                          </Box>
                        </TableCell>
                        <TableCell sx={{ color: 'white' }}>
                          <Box sx={{ display: 'flex', gap: 1 }}>
                            <Chip 
                              label={`${cluster.threats} threats`}
                              size="small"
                              sx={{ 
                                backgroundColor: alpha('#ef4444', 0.2),
                                color: '#ef4444',
                                fontSize: '0.7rem'
                              }}
                            />
                            <Chip 
                              label={`${cluster.vulnerabilities} vulns`}
                              size="small"
                              sx={{ 
                                backgroundColor: alpha('#f97316', 0.2),
                                color: '#f97316',
                                fontSize: '0.7rem'
                              }}
                            />
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 1 }}>
                            <Tooltip title="View Details">
                              <IconButton size="small" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                                <ViewIcon />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Refresh Scan">
                              <IconButton size="small" sx={{ color: '#3b82f6' }}>
                                <RefreshIcon />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </TableCell>
                      </motion.tr>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </motion.div>
          )}

          {/* Workloads Tab */}
          {activeTab === 1 && (
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.3 }}
            >
              <TableContainer component={Paper} sx={{ 
                backgroundColor: 'rgba(0,0,0,0.2)',
                border: '1px solid rgba(255,255,255,0.1)'
              }}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ color: 'rgba(255,255,255,0.8)', fontWeight: 600 }}>
                        Workload
                      </TableCell>
                      <TableCell sx={{ color: 'rgba(255,255,255,0.8)', fontWeight: 600 }}>
                        Status
                      </TableCell>
                      <TableCell sx={{ color: 'rgba(255,255,255,0.8)', fontWeight: 600 }}>
                        Protection
                      </TableCell>
                      <TableCell sx={{ color: 'rgba(255,255,255,0.8)', fontWeight: 600 }}>
                        Risk Level
                      </TableCell>
                      <TableCell sx={{ color: 'rgba(255,255,255,0.8)', fontWeight: 600 }}>
                        Security Issues
                      </TableCell>
                      <TableCell sx={{ color: 'rgba(255,255,255,0.8)', fontWeight: 600 }}>
                        Actions
                      </TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {workloadData.workloads.map((workload, index) => (
                      <motion.tr
                        key={workload.id}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.3, delay: index * 0.1 }}
                        component={TableRow}
                        sx={{ '&:hover': { backgroundColor: 'rgba(255,255,255,0.05)' } }}
                      >
                        <TableCell sx={{ color: 'white' }}>
                          <Box>
                            <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                              {workload.name}
                            </Typography>
                            <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.6)' }}>
                              {workload.namespace} • {workload.cluster} • {workload.replicas} replicas
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={workload.status}
                            size="small"
                            icon={workload.status === 'running' ? <CheckIcon /> : <ErrorIcon />}
                            sx={{ 
                              backgroundColor: alpha(getStatusColor(workload.status), 0.2),
                              color: getStatusColor(workload.status),
                              textTransform: 'capitalize'
                            }}
                          />
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={workload.protection}
                            size="small"
                            sx={{ 
                              backgroundColor: alpha(getProtectionColor(workload.protection), 0.2),
                              color: getProtectionColor(workload.protection),
                              textTransform: 'capitalize'
                            }}
                          />
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={workload.riskLevel}
                            size="small"
                            sx={{ 
                              backgroundColor: alpha(getRiskColor(workload.riskLevel), 0.2),
                              color: getRiskColor(workload.riskLevel),
                              textTransform: 'capitalize'
                            }}
                          />
                        </TableCell>
                        <TableCell sx={{ color: 'white' }}>
                          <Box sx={{ display: 'flex', gap: 1 }}>
                            {workload.threats > 0 && (
                              <Chip 
                                label={`${workload.threats} threats`}
                                size="small"
                                sx={{ 
                                  backgroundColor: alpha('#ef4444', 0.2),
                                  color: '#ef4444',
                                  fontSize: '0.7rem'
                                }}
                              />
                            )}
                            {workload.vulnerabilities > 0 && (
                              <Chip 
                                label={`${workload.vulnerabilities} vulns`}
                                size="small"
                                sx={{ 
                                  backgroundColor: alpha('#f97316', 0.2),
                                  color: '#f97316',
                                  fontSize: '0.7rem'
                                }}
                              />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 1 }}>
                            <Tooltip title="View Details">
                              <IconButton size="small" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                                <ViewIcon />
                              </IconButton>
                            </Tooltip>
                            {workload.protection === 'disabled' && (
                              <Tooltip title="Enable Protection">
                                <IconButton size="small" sx={{ color: '#10b981' }}>
                                  <ProtectionIcon />
                                </IconButton>
                              </Tooltip>
                            )}
                            {workload.riskLevel === 'critical' && (
                              <Tooltip title="Block Workload">
                                <IconButton size="small" sx={{ color: '#ef4444' }}>
                                  <BlockIcon />
                                </IconButton>
                              </Tooltip>
                            )}
                          </Box>
                        </TableCell>
                      </motion.tr>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </motion.div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
};

export default WorkloadProtection;
