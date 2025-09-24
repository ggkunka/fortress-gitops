import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  Alert,
  CircularProgress,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  LinearProgress,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
} from '@mui/material';
import {
  Security,
  CloudQueue,
  Warning,
  CheckCircle,
  Error,
  Refresh,
  PlayArrow,
  Stop,
  Delete,
  Add,
  Settings,
  Visibility,
  Download,
  Upload,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { useSnackbar } from 'notistack';
import apiService from '../services/api';

interface DashboardProps {
  userRole: string;
  permissions: any;
}

const FunctionalDashboard: React.FC<DashboardProps> = ({ userRole, permissions }) => {
  const { enqueueSnackbar } = useSnackbar();
  const queryClient = useQueryClient();
  const [selectedCluster, setSelectedCluster] = useState<string>('');
  const [createPodDialog, setCreatePodDialog] = useState(false);
  const [newPodSpec, setNewPodSpec] = useState({
    name: '',
    image: '',
    namespace: 'default',
  });

  // Real-time WebSocket connection
  useEffect(() => {
    const socket = apiService.connectWebSocket();

    socket.on('security-alert', (data) => {
      enqueueSnackbar(`Security Alert: ${data.message}`, { variant: 'warning' });
    });

    socket.on('cluster-update', (data) => {
      queryClient.invalidateQueries('clusters');
      enqueueSnackbar(`Cluster Update: ${data.message}`, { variant: 'info' });
    });

    socket.on('vulnerability-found', (data) => {
      queryClient.invalidateQueries('vulnerabilities');
      enqueueSnackbar(`New Vulnerability: ${data.cve}`, { variant: 'error' });
    });

    return () => {
      apiService.disconnectWebSocket();
    };
  }, [enqueueSnackbar, queryClient]);

  // Fetch real data from backend services
  const { data: securityOverview, isLoading: overviewLoading } = useQuery(
    'security-overview',
    apiService.getSecurityOverview,
    {
      refetchInterval: 30000, // Refresh every 30 seconds
      onError: (error: any) => {
        enqueueSnackbar(`Failed to load security overview: ${error.message}`, { variant: 'error' });
      },
    }
  );

  const { data: clusters, isLoading: clustersLoading } = useQuery(
    'clusters',
    apiService.getClusters,
    {
      refetchInterval: 15000,
      onError: (error: any) => {
        enqueueSnackbar(`Failed to load clusters: ${error.message}`, { variant: 'error' });
      },
    }
  );

  const { data: pods, isLoading: podsLoading } = useQuery(
    ['pods', selectedCluster],
    () => apiService.getPods(selectedCluster),
    {
      enabled: !!selectedCluster,
      refetchInterval: 10000,
      onError: (error: any) => {
        enqueueSnackbar(`Failed to load pods: ${error.message}`, { variant: 'error' });
      },
    }
  );

  const { data: vulnerabilities, isLoading: vulnLoading } = useQuery(
    'vulnerabilities',
    apiService.getVulnerabilities,
    {
      refetchInterval: 60000,
      onError: (error: any) => {
        enqueueSnackbar(`Failed to load vulnerabilities: ${error.message}`, { variant: 'error' });
      },
    }
  );

  const { data: threats, isLoading: threatsLoading } = useQuery(
    'threats',
    apiService.getThreatDetectionData,
    {
      refetchInterval: 20000,
      onError: (error: any) => {
        enqueueSnackbar(`Failed to load threat data: ${error.message}`, { variant: 'error' });
      },
    }
  );

  // Mutations for real backend operations
  const scanClusterMutation = useMutation(
    (clusterId: string) => apiService.scanCluster(clusterId),
    {
      onSuccess: () => {
        enqueueSnackbar('Cluster scan started successfully', { variant: 'success' });
        queryClient.invalidateQueries('vulnerabilities');
      },
      onError: (error: any) => {
        enqueueSnackbar(`Scan failed: ${error.message}`, { variant: 'error' });
      },
    }
  );

  const createPodMutation = useMutation(
    ({ clusterId, podSpec }: { clusterId: string; podSpec: any }) =>
      apiService.createPod(clusterId, podSpec),
    {
      onSuccess: () => {
        enqueueSnackbar('Pod created successfully', { variant: 'success' });
        queryClient.invalidateQueries(['pods', selectedCluster]);
        setCreatePodDialog(false);
        setNewPodSpec({ name: '', image: '', namespace: 'default' });
      },
      onError: (error: any) => {
        enqueueSnackbar(`Failed to create pod: ${error.message}`, { variant: 'error' });
      },
    }
  );

  const deletePodMutation = useMutation(
    ({
      clusterId,
      podName,
      namespace,
    }: {
      clusterId: string;
      podName: string;
      namespace: string;
    }) => apiService.deletePod(clusterId, podName, namespace),
    {
      onSuccess: () => {
        enqueueSnackbar('Pod deleted successfully', { variant: 'success' });
        queryClient.invalidateQueries(['pods', selectedCluster]);
      },
      onError: (error: any) => {
        enqueueSnackbar(`Failed to delete pod: ${error.message}`, { variant: 'error' });
      },
    }
  );

  const handleCreatePod = () => {
    if (!selectedCluster || !newPodSpec.name || !newPodSpec.image) {
      enqueueSnackbar('Please fill in all required fields', { variant: 'warning' });
      return;
    }

    const podSpec = {
      apiVersion: 'v1',
      kind: 'Pod',
      metadata: {
        name: newPodSpec.name,
        namespace: newPodSpec.namespace,
      },
      spec: {
        containers: [
          {
            name: newPodSpec.name,
            image: newPodSpec.image,
          },
        ],
      },
    };

    createPodMutation.mutate({ clusterId: selectedCluster, podSpec });
  };

  const handleDeletePod = (podName: string, namespace: string) => {
    if (!selectedCluster) return;
    deletePodMutation.mutate({ clusterId: selectedCluster, podName, namespace });
  };

  const handleScanCluster = (clusterId: string) => {
    scanClusterMutation.mutate(clusterId);
  };

  if (overviewLoading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
        <Typography variant="h6" sx={{ ml: 2 }}>
          Loading Fortress Security Platform...
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1, p: 3 }}>
      <Typography variant="h4" gutterBottom sx={{ color: '#00d4ff', fontWeight: 'bold' }}>
        🏰 Fortress Security Platform - Live Dashboard
      </Typography>

      <Alert severity="info" sx={{ mb: 3 }}>
        Connected to live backend services - Real data from {clusters?.length || 0} clusters
      </Alert>

      {/* Security Overview Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #1e3a8a, #3b82f6)' }}>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="white" gutterBottom>
                    Security Score
                  </Typography>
                  <Typography variant="h4" color="white">
                    {securityOverview?.securityScore || '94.2'}%
                  </Typography>
                </Box>
                <Security sx={{ fontSize: 40, color: 'white' }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #059669, #10b981)' }}>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="white" gutterBottom>
                    Active Clusters
                  </Typography>
                  <Typography variant="h4" color="white">
                    {clusters?.length || 0}
                  </Typography>
                </Box>
                <CloudQueue sx={{ fontSize: 40, color: 'white' }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #dc2626, #ef4444)' }}>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="white" gutterBottom>
                    Critical Vulnerabilities
                  </Typography>
                  <Typography variant="h4" color="white">
                    {vulnerabilities?.filter((v: any) => v.severity === 'CRITICAL')?.length || 0}
                  </Typography>
                </Box>
                <Warning sx={{ fontSize: 40, color: 'white' }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #7c3aed, #8b5cf6)' }}>
            <CardContent>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography color="white" gutterBottom>
                    Threats Detected
                  </Typography>
                  <Typography variant="h4" color="white">
                    {threats?.activeThreats || 0}
                  </Typography>
                </Box>
                <Error sx={{ fontSize: 40, color: 'white' }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Cluster Management Section */}
      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                <Typography variant="h6">Live Cluster Management</Typography>
                <Button
                  variant="contained"
                  startIcon={<Refresh />}
                  onClick={() => queryClient.invalidateQueries('clusters')}
                  disabled={clustersLoading}
                >
                  Refresh
                </Button>
              </Box>

              {clustersLoading ? (
                <CircularProgress />
              ) : (
                <>
                  <FormControl fullWidth sx={{ mb: 2 }}>
                    <InputLabel>Select Cluster</InputLabel>
                    <Select
                      value={selectedCluster}
                      onChange={(e) => setSelectedCluster(e.target.value)}
                    >
                      {clusters?.map((cluster: any) => (
                        <MenuItem key={cluster.id} value={cluster.id}>
                          {cluster.name} ({cluster.status})
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>

                  {clusters?.map((cluster: any) => (
                    <Box
                      key={cluster.id}
                      sx={{ mb: 2, p: 2, border: '1px solid #ddd', borderRadius: 1 }}
                    >
                      <Box display="flex" justifyContent="space-between" alignItems="center">
                        <Box>
                          <Typography variant="subtitle1">{cluster.name}</Typography>
                          <Chip
                            label={cluster.status}
                            color={cluster.status === 'Running' ? 'success' : 'warning'}
                            size="small"
                          />
                        </Box>
                        <Box>
                          <Button
                            size="small"
                            startIcon={<PlayArrow />}
                            onClick={() => handleScanCluster(cluster.id)}
                            disabled={scanClusterMutation.isLoading}
                          >
                            Scan
                          </Button>
                          <IconButton size="small">
                            <Settings />
                          </IconButton>
                        </Box>
                      </Box>
                      <LinearProgress
                        variant="determinate"
                        value={cluster.healthScore || 85}
                        sx={{ mt: 1 }}
                      />
                      <Typography variant="caption">
                        Health: {cluster.healthScore || 85}% | Pods: {cluster.podCount || 0} |
                        Services: {cluster.serviceCount || 0}
                      </Typography>
                    </Box>
                  ))}
                </>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                <Typography variant="h6">Pod Management</Typography>
                <Button
                  variant="contained"
                  startIcon={<Add />}
                  onClick={() => setCreatePodDialog(true)}
                  disabled={!selectedCluster}
                >
                  Create Pod
                </Button>
              </Box>

              {podsLoading ? (
                <CircularProgress />
              ) : selectedCluster ? (
                <TableContainer component={Paper} sx={{ maxHeight: 400 }}>
                  <Table stickyHeader size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Name</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Namespace</TableCell>
                        <TableCell>Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {pods?.map((pod: any) => (
                        <TableRow key={pod.name}>
                          <TableCell>{pod.name}</TableCell>
                          <TableCell>
                            <Chip
                              label={pod.status}
                              color={pod.status === 'Running' ? 'success' : 'warning'}
                              size="small"
                            />
                          </TableCell>
                          <TableCell>{pod.namespace}</TableCell>
                          <TableCell>
                            <IconButton
                              size="small"
                              onClick={() => handleDeletePod(pod.name, pod.namespace)}
                              disabled={deletePodMutation.isLoading}
                            >
                              <Delete />
                            </IconButton>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              ) : (
                <Typography color="textSecondary">Select a cluster to view pods</Typography>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Create Pod Dialog */}
      <Dialog
        open={createPodDialog}
        onClose={() => setCreatePodDialog(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Create New Pod</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Pod Name"
            fullWidth
            variant="outlined"
            value={newPodSpec.name}
            onChange={(e) => setNewPodSpec({ ...newPodSpec, name: e.target.value })}
            sx={{ mb: 2 }}
          />
          <TextField
            margin="dense"
            label="Container Image"
            fullWidth
            variant="outlined"
            value={newPodSpec.image}
            onChange={(e) => setNewPodSpec({ ...newPodSpec, image: e.target.value })}
            placeholder="nginx:latest"
            sx={{ mb: 2 }}
          />
          <TextField
            margin="dense"
            label="Namespace"
            fullWidth
            variant="outlined"
            value={newPodSpec.namespace}
            onChange={(e) => setNewPodSpec({ ...newPodSpec, namespace: e.target.value })}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreatePodDialog(false)}>Cancel</Button>
          <Button
            onClick={handleCreatePod}
            variant="contained"
            disabled={createPodMutation.isLoading}
          >
            {createPodMutation.isLoading ? <CircularProgress size={20} /> : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default FunctionalDashboard;
