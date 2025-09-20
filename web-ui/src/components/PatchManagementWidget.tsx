import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  ListItemSecondaryAction,
  IconButton,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  LinearProgress,
  Alert,
  Tooltip,
  Grid,
  Divider,
  Avatar,
  Badge,
  Menu,
  Tab,
  Tabs,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Build as BuildIcon,
  Security as SecurityIcon,
  CloudUpload as UploadIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Schedule as ScheduleIcon,
  PlayArrow as DeployIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  Download as DownloadIcon,
  Visibility as ViewIcon,
  MoreVert as MoreIcon,
  BugReport as BugIcon,
  Code as CodeIcon,
  Storage as StorageIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { PatchInfo, PatchBuild, PatchDeployment, UserRole } from '../types/security';

interface PatchManagementWidgetProps {
  userRole?: UserRole;
  height?: number;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => (
  <div hidden={value !== index}>
    {value === index && <Box sx={{ py: 2 }}>{children}</Box>}
  </div>
);

const PatchManagementWidget: React.FC<PatchManagementWidgetProps> = ({
  userRole = 'admin',
  height = 500,
}) => {
  const theme = useTheme();
  const queryClient = useQueryClient();
  const [tabValue, setTabValue] = useState(0);
  const [selectedPatch, setSelectedPatch] = useState<PatchInfo | null>(null);
  const [isPatchDialogOpen, setIsPatchDialogOpen] = useState(false);
  const [isBuildDialogOpen, setIsBuildDialogOpen] = useState(false);
  const [isDeployDialogOpen, setIsDeployDialogOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  // Mock data - replace with actual API calls
  const mockPatches: PatchInfo[] = [
    {
      id: 'patch-001',
      cveId: 'CVE-2024-1234',
      title: 'nginx Remote Code Execution Fix',
      description: 'Critical security patch for nginx vulnerability allowing remote code execution',
      severity: 'critical',
      affectedImages: ['nginx:1.20', 'nginx:1.21'],
      patchVersion: '1.21.6-security',
      releaseDate: new Date('2024-01-15'),
      testingStatus: 'tested',
      deploymentStatus: 'pending',
      rollbackAvailable: true,
      impactAssessment: {
        riskLevel: 'high',
        affectedServices: ['web-frontend', 'api-gateway'],
        downtime: '< 5 minutes',
        rollbackTime: '< 2 minutes',
      },
      approvals: {
        securityTeam: true,
        devOpsTeam: true,
        businessOwner: false,
      },
      metadata: {
        buildTime: '2 minutes',
        testDuration: '15 minutes',
        confidence: 95,
      },
    },
    {
      id: 'patch-002',
      cveId: 'CVE-2024-5678',
      title: 'Node.js Privilege Escalation Fix',
      description: 'High severity patch for Node.js privilege escalation vulnerability',
      severity: 'high',
      affectedImages: ['node:16', 'node:18'],
      patchVersion: '18.19.1-security',
      releaseDate: new Date('2024-01-20'),
      testingStatus: 'testing',
      deploymentStatus: 'building',
      rollbackAvailable: true,
      impactAssessment: {
        riskLevel: 'medium',
        affectedServices: ['api-server', 'worker-service'],
        downtime: '< 10 minutes',
        rollbackTime: '< 5 minutes',
      },
      approvals: {
        securityTeam: true,
        devOpsTeam: false,
        businessOwner: false,
      },
      metadata: {
        buildTime: '5 minutes',
        testDuration: '30 minutes',
        confidence: 85,
      },
    },
  ];

  const mockBuilds: PatchBuild[] = [
    {
      id: 'build-001',
      patchId: 'patch-001',
      baseImage: 'nginx:1.21',
      patchedImage: 'nginx:1.21.6-security-patched',
      buildStatus: 'built',
      buildLogs: [
        'Starting build process...',
        'Pulling base image nginx:1.21',
        'Applying security patches...',
        'Running security scan...',
        'Build completed successfully',
      ],
      testResults: {
        securityScan: {
          passed: true,
          vulnerabilities: 0,
          report: 'No vulnerabilities found',
        },
        functionalTest: {
          passed: true,
          results: 'All tests passed',
        },
        performanceTest: {
          passed: true,
          metrics: {
            cpuUsage: 15,
            memoryUsage: 128,
            responseTime: 45,
          },
        },
      },
      createdAt: new Date('2024-01-15T10:00:00Z'),
      completedAt: new Date('2024-01-15T10:05:00Z'),
      size: 142857600, // ~136MB
      layers: ['sha256:abc123...', 'sha256:def456...', 'sha256:ghi789...'],
    },
  ];

  // Fetch patches
  const { data: patches = mockPatches, isLoading: patchesLoading } = useQuery(
    'patches',
    () => Promise.resolve(mockPatches),
    { refetchInterval: 30000 }
  );

  // Fetch builds
  const { data: builds = mockBuilds, isLoading: buildsLoading } = useQuery(
    'patch-builds',
    () => Promise.resolve(mockBuilds),
    { refetchInterval: 10000 }
  );

  // Mutations
  const buildPatchMutation = useMutation(
    (patchId: string) => {
      // Mock API call
      return new Promise(resolve => setTimeout(resolve, 2000));
    },
    {
      onSuccess: () => {
        queryClient.invalidateQueries('patch-builds');
      },
    }
  );

  const deployPatchMutation = useMutation(
    ({ patchId, clusterId }: { patchId: string; clusterId: string }) => {
      // Mock API call
      return new Promise(resolve => setTimeout(resolve, 3000));
    },
    {
      onSuccess: () => {
        queryClient.invalidateQueries('patch-deployments');
      },
    }
  );

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return theme.palette.error.main;
      case 'high': return theme.palette.warning.main;
      case 'medium': return theme.palette.info.main;
      case 'low': return theme.palette.success.main;
      default: return theme.palette.grey[500];
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'built':
      case 'tested':
      case 'deployed': return theme.palette.success.main;
      case 'building':
      case 'testing':
      case 'deploying': return theme.palette.warning.main;
      case 'failed': return theme.palette.error.main;
      default: return theme.palette.grey[500];
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'built':
      case 'tested':
      case 'deployed': return <CheckIcon />;
      case 'building':
      case 'testing':
      case 'deploying': return <ScheduleIcon />;
      case 'failed': return <ErrorIcon />;
      default: return <ScheduleIcon />;
    }
  };

  const handleBuildPatch = (patchId: string) => {
    buildPatchMutation.mutate(patchId);
  };

  const handleDeployPatch = (patchId: string, clusterId: string) => {
    deployPatchMutation.mutate({ patchId, clusterId });
  };

  const formatFileSize = (bytes: number) => {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  return (
    <Card sx={{ height, display: 'flex', flexDirection: 'column' }}>
      <CardContent sx={{ flexGrow: 1, p: 0 }}>
        {/* Header */}
        <Box sx={{ p: 2, borderBottom: `1px solid ${theme.palette.divider}` }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <Avatar sx={{ bgcolor: theme.palette.primary.main, mr: 2 }}>
                <BuildIcon />
              </Avatar>
              <Box>
                <Typography variant="h6" sx={{ fontWeight: 600 }}>
                  Patch Management
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Build and deploy security patches
                </Typography>
              </Box>
            </Box>
            <Box>
              <Tooltip title="Refresh">
                <IconButton size="small" onClick={() => queryClient.invalidateQueries()}>
                  <RefreshIcon />
                </IconButton>
              </Tooltip>
              {userRole === 'admin' && (
                <Tooltip title="Create Patch">
                  <IconButton size="small" onClick={() => setIsPatchDialogOpen(true)}>
                    <BuildIcon />
                  </IconButton>
                </Tooltip>
              )}
            </Box>
          </Box>
        </Box>

        {/* Tabs */}
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={tabValue} onChange={(_, newValue) => setTabValue(newValue)} variant="fullWidth">
            <Tab
              label={
                <Badge badgeContent={patches.length} color="primary">
                  Patches
                </Badge>
              }
            />
            <Tab
              label={
                <Badge badgeContent={builds.length} color="secondary">
                  Builds
                </Badge>
              }
            />
          </Tabs>
        </Box>

        {/* Patches Tab */}
        <TabPanel value={tabValue} index={0}>
          <Box sx={{ maxHeight: height - 200, overflow: 'auto' }}>
            <AnimatePresence>
              {patches.map((patch, index) => (
                <motion.div
                  key={patch.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.3, delay: index * 0.1 }}
                >
                  <ListItem
                    sx={{
                      border: `1px solid ${theme.palette.divider}`,
                      borderRadius: 1,
                      mb: 1,
                      bgcolor: alpha(getSeverityColor(patch.severity), 0.05),
                    }}
                  >
                    <ListItemIcon>
                      <Avatar
                        sx={{
                          bgcolor: getSeverityColor(patch.severity),
                          width: 32,
                          height: 32,
                        }}
                      >
                        <BugIcon sx={{ fontSize: 18 }} />
                      </Avatar>
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                            {patch.title}
                          </Typography>
                          <Chip
                            label={patch.severity.toUpperCase()}
                            size="small"
                            sx={{
                              bgcolor: alpha(getSeverityColor(patch.severity), 0.2),
                              color: getSeverityColor(patch.severity),
                            }}
                          />
                        </Box>
                      }
                      secondary={
                        <Box sx={{ mt: 1 }}>
                          <Typography variant="caption" color="text.secondary">
                            {patch.cveId} • {patch.affectedImages.length} images affected
                          </Typography>
                          <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                            <Chip
                              label={`Testing: ${patch.testingStatus}`}
                              size="small"
                              color={patch.testingStatus === 'tested' ? 'success' : 'warning'}
                              variant="outlined"
                            />
                            <Chip
                              label={`Deploy: ${patch.deploymentStatus}`}
                              size="small"
                              color={patch.deploymentStatus === 'deployed' ? 'success' : 'default'}
                              variant="outlined"
                            />
                          </Box>
                        </Box>
                      }
                    />
                    <ListItemSecondaryAction>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {userRole === 'admin' && patch.testingStatus === 'tested' && (
                          <Tooltip title="Build Patch">
                            <IconButton
                              size="small"
                              onClick={() => handleBuildPatch(patch.id)}
                              disabled={buildPatchMutation.isLoading}
                            >
                              <BuildIcon />
                            </IconButton>
                          </Tooltip>
                        )}
                        {userRole === 'admin' && patch.deploymentStatus === 'built' && (
                          <Tooltip title="Deploy Patch">
                            <IconButton
                              size="small"
                              onClick={() => setIsDeployDialogOpen(true)}
                            >
                              <DeployIcon />
                            </IconButton>
                          </Tooltip>
                        )}
                        <Tooltip title="View Details">
                          <IconButton
                            size="small"
                            onClick={() => setSelectedPatch(patch)}
                          >
                            <ViewIcon />
                          </IconButton>
                        </Tooltip>
                        <IconButton
                          size="small"
                          onClick={(e) => setAnchorEl(e.currentTarget)}
                        >
                          <MoreIcon />
                        </IconButton>
                      </Box>
                    </ListItemSecondaryAction>
                  </ListItem>
                </motion.div>
              ))}
            </AnimatePresence>
          </Box>
        </TabPanel>

        {/* Builds Tab */}
        <TabPanel value={tabValue} index={1}>
          <Box sx={{ maxHeight: height - 200, overflow: 'auto' }}>
            <AnimatePresence>
              {builds.map((build, index) => (
                <motion.div
                  key={build.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.3, delay: index * 0.1 }}
                >
                  <ListItem
                    sx={{
                      border: `1px solid ${theme.palette.divider}`,
                      borderRadius: 1,
                      mb: 1,
                      bgcolor: alpha(getStatusColor(build.buildStatus), 0.05),
                    }}
                  >
                    <ListItemIcon>
                      <Avatar
                        sx={{
                          bgcolor: getStatusColor(build.buildStatus),
                          width: 32,
                          height: 32,
                        }}
                      >
                        {getStatusIcon(build.buildStatus)}
                      </Avatar>
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                            {build.patchedImage}
                          </Typography>
                          <Chip
                            label={build.buildStatus.toUpperCase()}
                            size="small"
                            sx={{
                              bgcolor: alpha(getStatusColor(build.buildStatus), 0.2),
                              color: getStatusColor(build.buildStatus),
                            }}
                          />
                        </Box>
                      }
                      secondary={
                        <Box sx={{ mt: 1 }}>
                          <Typography variant="caption" color="text.secondary">
                            Base: {build.baseImage} • Size: {formatFileSize(build.size)}
                          </Typography>
                          {build.buildStatus === 'building' && (
                            <LinearProgress sx={{ mt: 1, height: 4, borderRadius: 2 }} />
                          )}
                          {build.testResults && (
                            <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                              <Chip
                                label={`Security: ${build.testResults.securityScan.passed ? 'Pass' : 'Fail'}`}
                                size="small"
                                color={build.testResults.securityScan.passed ? 'success' : 'error'}
                                variant="outlined"
                              />
                              <Chip
                                label={`Functional: ${build.testResults.functionalTest.passed ? 'Pass' : 'Fail'}`}
                                size="small"
                                color={build.testResults.functionalTest.passed ? 'success' : 'error'}
                                variant="outlined"
                              />
                              <Chip
                                label={`Performance: ${build.testResults.performanceTest.passed ? 'Pass' : 'Fail'}`}
                                size="small"
                                color={build.testResults.performanceTest.passed ? 'success' : 'error'}
                                variant="outlined"
                              />
                            </Box>
                          )}
                        </Box>
                      }
                    />
                    <ListItemSecondaryAction>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Tooltip title="View Logs">
                          <IconButton size="small">
                            <CodeIcon />
                          </IconButton>
                        </Tooltip>
                        {build.buildStatus === 'built' && (
                          <Tooltip title="Push to Registry">
                            <IconButton size="small">
                              <UploadIcon />
                            </IconButton>
                          </Tooltip>
                        )}
                        <Tooltip title="Download">
                          <IconButton size="small">
                            <DownloadIcon />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </ListItemSecondaryAction>
                  </ListItem>
                </motion.div>
              ))}
            </AnimatePresence>
          </Box>
        </TabPanel>
      </CardContent>

      {/* Patch Details Dialog */}
      <Dialog
        open={!!selectedPatch}
        onClose={() => setSelectedPatch(null)}
        maxWidth="md"
        fullWidth
      >
        {selectedPatch && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <Avatar sx={{ bgcolor: getSeverityColor(selectedPatch.severity) }}>
                  <BugIcon />
                </Avatar>
                <Box>
                  <Typography variant="h6">{selectedPatch.title}</Typography>
                  <Typography variant="caption" color="text.secondary">
                    {selectedPatch.cveId}
                  </Typography>
                </Box>
              </Box>
            </DialogTitle>
            <DialogContent>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    Description
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    {selectedPatch.description}
                  </Typography>

                  <Typography variant="subtitle2" gutterBottom>
                    Affected Images
                  </Typography>
                  <Box sx={{ mb: 2 }}>
                    {selectedPatch.affectedImages.map((image) => (
                      <Chip key={image} label={image} size="small" sx={{ mr: 1, mb: 1 }} />
                    ))}
                  </Box>

                  <Typography variant="subtitle2" gutterBottom>
                    Impact Assessment
                  </Typography>
                  <List dense>
                    <ListItem>
                      <ListItemText
                        primary="Risk Level"
                        secondary={selectedPatch.impactAssessment.riskLevel.toUpperCase()}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="Estimated Downtime"
                        secondary={selectedPatch.impactAssessment.downtime}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemText
                        primary="Rollback Time"
                        secondary={selectedPatch.impactAssessment.rollbackTime}
                      />
                    </ListItem>
                  </List>
                </Grid>

                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    Approvals
                  </Typography>
                  <List dense>
                    <ListItem>
                      <ListItemIcon>
                        {selectedPatch.approvals.securityTeam ? (
                          <CheckIcon color="success" />
                        ) : (
                          <ScheduleIcon color="warning" />
                        )}
                      </ListItemIcon>
                      <ListItemText primary="Security Team" />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        {selectedPatch.approvals.devOpsTeam ? (
                          <CheckIcon color="success" />
                        ) : (
                          <ScheduleIcon color="warning" />
                        )}
                      </ListItemIcon>
                      <ListItemText primary="DevOps Team" />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        {selectedPatch.approvals.businessOwner ? (
                          <CheckIcon color="success" />
                        ) : (
                          <ScheduleIcon color="warning" />
                        )}
                      </ListItemIcon>
                      <ListItemText primary="Business Owner" />
                    </ListItem>
                  </List>

                  <Divider sx={{ my: 2 }} />

                  <Typography variant="subtitle2" gutterBottom>
                    Status
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                    <Chip
                      label={`Testing: ${selectedPatch.testingStatus}`}
                      color={selectedPatch.testingStatus === 'tested' ? 'success' : 'warning'}
                    />
                    <Chip
                      label={`Deployment: ${selectedPatch.deploymentStatus}`}
                      color={selectedPatch.deploymentStatus === 'deployed' ? 'success' : 'default'}
                    />
                  </Box>

                  {selectedPatch.rollbackAvailable && (
                    <Alert severity="info" sx={{ mt: 2 }}>
                      Rollback is available for this patch
                    </Alert>
                  )}
                </Grid>
              </Grid>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setSelectedPatch(null)}>Close</Button>
              {userRole === 'admin' && selectedPatch.testingStatus === 'tested' && (
                <Button
                  variant="contained"
                  startIcon={<BuildIcon />}
                  onClick={() => handleBuildPatch(selectedPatch.id)}
                  disabled={buildPatchMutation.isLoading}
                >
                  Build Patch
                </Button>
              )}
            </DialogActions>
          </>
        )}
      </Dialog>

      {/* Context Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={() => setAnchorEl(null)}
      >
        <MenuItem onClick={() => setAnchorEl(null)}>
          <ListItemIcon>
            <ViewIcon />
          </ListItemIcon>
          View Details
        </MenuItem>
        <MenuItem onClick={() => setAnchorEl(null)}>
          <ListItemIcon>
            <TimelineIcon />
          </ListItemIcon>
          View Timeline
        </MenuItem>
        {userRole === 'admin' && (
          <MenuItem onClick={() => setAnchorEl(null)}>
            <ListItemIcon>
              <BuildIcon />
            </ListItemIcon>
            Build Patch
          </MenuItem>
        )}
      </Menu>
    </Card>
  );
};

export default PatchManagementWidget;
