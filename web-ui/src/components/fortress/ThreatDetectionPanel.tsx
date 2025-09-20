import React, { useState } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Avatar,
  Chip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  IconButton,
  Menu,
  MenuItem,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckIcon,
  Notifications as AlertIcon,
  MoreVert as MoreIcon,
  Block as BlockIcon,
  Visibility as InvestigateIcon,
  Done as ResolveIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';

const ThreatDetectionPanel: React.FC = () => {
  const theme = useTheme();
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null);
  const [selectedThreat, setSelectedThreat] = useState<number | null>(null);

  const threatData = {
    active: 7,
    resolved: 156,
    investigating: 3,
    falsePositives: 12,
    recentThreats: [
      {
        id: 1,
        severity: 'critical',
        title: 'Malicious Container Execution',
        description: 'Suspicious process execution detected in production container',
        source: 'Runtime Detection',
        time: '2 min ago',
        status: 'active'
      },
      {
        id: 2,
        severity: 'high',
        title: 'Privilege Escalation Attempt',
        description: 'Unauthorized privilege escalation detected in k8s-cluster-east-1',
        source: 'Behavioral Analysis',
        time: '15 min ago',
        status: 'investigating'
      },
      {
        id: 3,
        severity: 'medium',
        title: 'Anomalous Network Traffic',
        description: 'Unusual outbound connections from web-app pods',
        source: 'Network Monitoring',
        time: '1 hour ago',
        status: 'investigating'
      },
      {
        id: 4,
        severity: 'high',
        title: 'Crypto Mining Activity',
        description: 'High CPU usage pattern consistent with crypto mining',
        source: 'Resource Monitoring',
        time: '2 hours ago',
        status: 'resolved'
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
      case 'active': return '#ef4444';
      case 'investigating': return '#eab308';
      case 'resolved': return '#10b981';
      default: return '#6b7280';
    }
  };

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, threatId: number) => {
    setMenuAnchor(event.currentTarget);
    setSelectedThreat(threatId);
  };

  const handleMenuClose = () => {
    setMenuAnchor(null);
    setSelectedThreat(null);
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.5, delay: 0.2 }}
    >
      <Card sx={{ 
        background: 'linear-gradient(135deg, #1e293b, #334155)', 
        border: '1px solid rgba(255,255,255,0.1)',
        height: '100%'
      }}>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 3, display: 'flex', alignItems: 'center' }}>
            <SecurityIcon sx={{ mr: 1, color: '#ef4444' }} />
            Threat Detection
          </Typography>

          {/* Threat Summary */}
          <Box sx={{ display: 'flex', justifyContent: 'space-around', mb: 3 }}>
            <Box sx={{ textAlign: 'center' }}>
              <Avatar sx={{ 
                width: 48, 
                height: 48, 
                mx: 'auto', 
                mb: 1, 
                backgroundColor: '#ef4444',
                animation: 'pulse 2s infinite'
              }}>
                <AlertIcon />
              </Avatar>
              <Typography variant="h4" sx={{ fontWeight: 700, color: '#ef4444' }}>
                {threatData.active}
              </Typography>
              <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                Active Threats
              </Typography>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Avatar sx={{ 
                width: 48, 
                height: 48, 
                mx: 'auto', 
                mb: 1, 
                backgroundColor: '#10b981' 
              }}>
                <CheckIcon />
              </Avatar>
              <Typography variant="h4" sx={{ fontWeight: 700, color: '#10b981' }}>
                {threatData.resolved}
              </Typography>
              <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                Resolved
              </Typography>
            </Box>
          </Box>

          {/* Status Chips */}
          <Box sx={{ display: 'flex', gap: 1, mb: 3, flexWrap: 'wrap' }}>
            <Chip 
              label={`${threatData.investigating} Investigating`}
              size="small"
              sx={{ 
                backgroundColor: alpha('#eab308', 0.2),
                color: '#eab308'
              }}
            />
            <Chip 
              label={`${threatData.falsePositives} False Positives`}
              size="small"
              sx={{ 
                backgroundColor: alpha('#6b7280', 0.2),
                color: '#9ca3af'
              }}
            />
          </Box>

          {/* Recent Threats */}
          <Typography variant="subtitle2" sx={{ mb: 2, color: 'rgba(255,255,255,0.8)' }}>
            Recent Threats
          </Typography>
          <List sx={{ maxHeight: 300, overflow: 'auto' }}>
            {threatData.recentThreats.map((threat, index) => (
              <motion.div
                key={threat.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3, delay: index * 0.1 }}
              >
                <ListItem 
                  sx={{ 
                    px: 0, 
                    py: 1,
                    backgroundColor: 'rgba(0,0,0,0.2)',
                    borderRadius: 2,
                    mb: 1,
                    border: `1px solid ${alpha(getSeverityColor(threat.severity), 0.3)}`
                  }}
                >
                  <ListItemIcon>
                    <Avatar sx={{ 
                      width: 32, 
                      height: 32, 
                      backgroundColor: getSeverityColor(threat.severity) 
                    }}>
                      {threat.severity === 'critical' ? <ErrorIcon /> : <WarningIcon />}
                    </Avatar>
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                          {threat.title}
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                          <Chip 
                            label={threat.severity.toUpperCase()}
                            size="small"
                            sx={{ 
                              backgroundColor: alpha(getSeverityColor(threat.severity), 0.2),
                              color: getSeverityColor(threat.severity),
                              fontSize: '0.7rem'
                            }}
                          />
                          <IconButton 
                            size="small" 
                            onClick={(e) => handleMenuOpen(e, threat.id)}
                            sx={{ color: 'rgba(255,255,255,0.7)' }}
                          >
                            <MoreIcon />
                          </IconButton>
                        </Box>
                      </Box>
                    }
                    secondary={
                      <Box sx={{ mt: 1 }}>
                        <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)', mb: 1 }}>
                          {threat.description}
                        </Typography>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.5)' }}>
                            {threat.source} • {threat.time}
                          </Typography>
                          <Chip 
                            label={threat.status}
                            size="small"
                            sx={{ 
                              backgroundColor: alpha(getStatusColor(threat.status), 0.2),
                              color: getStatusColor(threat.status),
                              fontSize: '0.7rem'
                            }}
                          />
                        </Box>
                      </Box>
                    }
                  />
                </ListItem>
              </motion.div>
            ))}
          </List>

          {/* Action Menu */}
          <Menu
            anchorEl={menuAnchor}
            open={Boolean(menuAnchor)}
            onClose={handleMenuClose}
            PaperProps={{
              sx: {
                backgroundColor: '#1e293b',
                border: '1px solid rgba(255,255,255,0.1)',
                color: 'white'
              }
            }}
          >
            <MenuItem onClick={handleMenuClose}>
              <InvestigateIcon sx={{ mr: 1 }} />
              Investigate
            </MenuItem>
            <MenuItem onClick={handleMenuClose}>
              <BlockIcon sx={{ mr: 1 }} />
              Block Source
            </MenuItem>
            <MenuItem onClick={handleMenuClose}>
              <ResolveIcon sx={{ mr: 1 }} />
              Mark Resolved
            </MenuItem>
          </Menu>
        </CardContent>
      </Card>
    </motion.div>
  );
};

export default ThreatDetectionPanel;
