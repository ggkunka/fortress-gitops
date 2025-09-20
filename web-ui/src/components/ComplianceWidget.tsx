import React from 'react';
import {
  Card,
  CardContent,
  Typography,
  LinearProgress,
  Box,
  Avatar,
  IconButton,
  Tooltip,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Chip,
} from '@mui/material';
import {
  Gavel as ComplianceIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';

const ComplianceWidget: React.FC = () => {
  const theme = useTheme();

  const complianceFrameworks = [
    { name: 'SOC 2', score: 92, status: 'compliant' },
    { name: 'PCI DSS', score: 88, status: 'compliant' },
    { name: 'GDPR', score: 76, status: 'partial' },
    { name: 'HIPAA', score: 95, status: 'compliant' },
  ];

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant': return theme.palette.success.main;
      case 'partial': return theme.palette.warning.main;
      case 'non-compliant': return theme.palette.error.main;
      default: return theme.palette.grey[500];
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'compliant': return <CheckIcon />;
      case 'partial': return <WarningIcon />;
      case 'non-compliant': return <ErrorIcon />;
      default: return <WarningIcon />;
    }
  };

  return (
    <Card sx={{ height: 500 }}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <Avatar sx={{ bgcolor: theme.palette.info.main, mr: 2 }}>
              <ComplianceIcon />
            </Avatar>
            <Box>
              <Typography variant="h6" sx={{ fontWeight: 600 }}>
                Compliance Status
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Regulatory compliance overview
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
          {complianceFrameworks.map((framework) => (
            <ListItem key={framework.name} sx={{ px: 0, flexDirection: 'column', alignItems: 'stretch' }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%', mb: 1 }}>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <Box sx={{ color: getStatusColor(framework.status), mr: 1 }}>
                    {getStatusIcon(framework.status)}
                  </Box>
                  <Typography variant="subtitle2">{framework.name}</Typography>
                </Box>
                <Typography variant="h6" sx={{ fontWeight: 600 }}>
                  {framework.score}%
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={framework.score}
                sx={{
                  height: 6,
                  borderRadius: 3,
                  bgcolor: theme.palette.grey[200],
                  '& .MuiLinearProgress-bar': {
                    bgcolor: getStatusColor(framework.status),
                  },
                }}
              />
            </ListItem>
          ))}
        </List>
      </CardContent>
    </Card>
  );
};

export default ComplianceWidget;
