import React from 'react';
import {
  Card,
  CardContent,
  Typography,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Chip,
  Avatar,
  Box,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Security as ThreatIcon,
  Warning as WarningIcon,
  Refresh as RefreshIcon,
  TrendingUp as TrendingUpIcon,
} from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';

const ThreatIntelligenceWidget: React.FC = () => {
  const theme = useTheme();

  const mockThreats = [
    {
      id: '1',
      title: 'APT29 Campaign Detected',
      severity: 'critical',
      confidence: 95,
      source: 'MITRE ATT&CK',
      indicators: 3,
    },
    {
      id: '2',
      title: 'Malicious IP Activity',
      severity: 'high',
      confidence: 87,
      source: 'Threat Intel Feed',
      indicators: 5,
    },
    {
      id: '3',
      title: 'Suspicious Domain Registration',
      severity: 'medium',
      confidence: 72,
      source: 'DNS Intelligence',
      indicators: 2,
    },
  ];

  return (
    <Card sx={{ height: 500 }}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <Avatar sx={{ bgcolor: theme.palette.warning.main, mr: 2 }}>
              <ThreatIcon />
            </Avatar>
            <Box>
              <Typography variant="h6" sx={{ fontWeight: 600 }}>
                Threat Intelligence
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Latest security threats
              </Typography>
            </Box>
          </Box>
          <Tooltip title="Refresh">
            <IconButton size="small">
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Box>

        <List>
          {mockThreats.map((threat) => (
            <ListItem key={threat.id} sx={{ px: 0 }}>
              <ListItemIcon>
                <WarningIcon 
                  color={threat.severity === 'critical' ? 'error' : 
                         threat.severity === 'high' ? 'warning' : 'info'} 
                />
              </ListItemIcon>
              <ListItemText
                primary={threat.title}
                secondary={
                  <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                    <Chip 
                      label={`${threat.confidence}% confidence`} 
                      size="small" 
                      variant="outlined" 
                    />
                    <Chip 
                      label={`${threat.indicators} indicators`} 
                      size="small" 
                      variant="outlined" 
                    />
                  </Box>
                }
              />
            </ListItem>
          ))}
        </List>
      </CardContent>
    </Card>
  );
};

export default ThreatIntelligenceWidget;
