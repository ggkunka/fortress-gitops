import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Grid,
  Chip,
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
  Alert,
  Tooltip,
  LinearProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Fab,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
  CloudQueue as CloudIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Settings as SettingsIcon,
  Visibility as ViewIcon,
  PlayArrow as TestIcon,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { clusterApi } from '../../services/clusterApi';
import { ClusterConfig, ClusterStatus } from '../../types';

const ClustersPage: React.FC = () => {
  const [selectedCluster, setSelectedCluster] = useState<ClusterConfig | null>(null);
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false);
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);
  const [testResults, setTestResults] = useState<{ [key: string]: any }>({});
  const queryClient = useQueryClient();

  // Fetch clusters
  const { data: clusters = [], isLoading, error } = useQuery(
    'clusters',
    clusterApi.getClusters,
    { refetchInterval: 30000 } // Refresh every 30 seconds
  );

  // Fetch cluster statuses
  const { data: clusterStatuses = [] } = useQuery(
    'cluster-statuses',
    clusterApi.getClusterStatuses,
    { refetchInterval: 10000 } // Refresh every 10 seconds
  );

  // Create cluster mutation
  const createClusterMutation = useMutation(clusterApi.createCluster, {
    onSuccess: () => {
      queryClient.invalidateQueries('clusters');
      setIsCreateDialogOpen(false);
    },
  });

  // Update cluster mutation
  const updateClusterMutation = useMutation(
    ({ id, data }: { id: string; data: Partial<ClusterConfig> }) =>
      clusterApi.updateCluster(id, data),
    {
      onSuccess: () => {
        queryClient.invalidateQueries('clusters');
        setIsEditDialogOpen(false);
        setSelectedCluster(null);
      },
    }
  );

  // Delete cluster mutation
  const deleteClusterMutation = useMutation(clusterApi.deleteCluster, {
    onSuccess: () => {
      queryClient.invalidateQueries('clusters');
      setIsDeleteDialogOpen(false);
      setSelectedCluster(null);
    },
  });

  // Test connection mutation
  const testConnectionMutation = useMutation(clusterApi.testConnection, {
    onSuccess: (result, clusterId) => {
      setTestResults(prev => ({ ...prev, [clusterId]: result }));
    },
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'connected':
        return 'success';
      case 'connecting':
        return 'warning';
      case 'disconnected':
      case 'error':
        return 'error';
      default:
        return 'default';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'connected':
        return <CheckCircleIcon color="success" />;
      case 'connecting':
        return <WarningIcon color="warning" />;
      case 'disconnected':
      case 'error':
        return <ErrorIcon color="error" />;
      default:
        return <CloudIcon />;
    }
  };

  const getClusterStatus = (clusterId: string): ClusterStatus | undefined => {
    return clusterStatuses.find(status => status.clusterId === clusterId);
  };

  const handleTestConnection = (clusterId: string) => {
    testConnectionMutation.mutate(clusterId);
  };

  const handleDeleteCluster = () => {
    if (selectedCluster) {
      deleteClusterMutation.mutate(selectedCluster.id);
    }
  };

  if (isLoading) {
    return (
      <Box sx={{ width: '100%', mt: 2 }}>
        <LinearProgress />
        <Typography variant="h6" sx={{ mt: 2, textAlign: 'center' }}>
          Loading clusters...
        </Typography>
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ mt: 2 }}>
        Failed to load clusters. Please try again.
      </Alert>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1">
          Kubernetes Clusters
        </Typography>
        <Box>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => queryClient.invalidateQueries('clusters')}
            sx={{ mr: 2 }}
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setIsCreateDialogOpen(true)}
          >
            Add Cluster
          </Button>
        </Box>
      </Box>

      {/* Clusters Grid */}
      <Grid container spacing={3}>
        {clusters.map((cluster) => {
          const status = getClusterStatus(cluster.id);
          const testResult = testResults[cluster.id];
          
          return (
            <Grid item xs={12} md={6} lg={4} key={cluster.id}>
              <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                <CardContent sx={{ flexGrow: 1 }}>
                  {/* Cluster Header */}
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                    <Box>
                      <Typography variant="h6" component="h2" gutterBottom>
                        {cluster.name}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" gutterBottom>
                        {cluster.description}
                      </Typography>
                    </Box>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      {getStatusIcon(cluster.status)}
                      <Chip
                        label={cluster.status}
                        color={getStatusColor(cluster.status) as any}
                        size="small"
                        sx={{ ml: 1 }}
                      />
                    </Box>
                  </Box>

                  {/* Cluster Details */}
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      <strong>Endpoint:</strong> {cluster.endpoint}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      <strong>Provider:</strong> {cluster.provider || 'Unknown'}
                    </Typography>
                    {cluster.version && (
                      <Typography variant="body2" color="text.secondary">
                        <strong>Version:</strong> {cluster.version}
                      </Typography>
                    )}
                    {status && (
                      <Typography variant="body2" color="text.secondary">
                        <strong>Nodes:</strong> {status.nodes.length}
                      </Typography>
                    )}
                  </Box>

                  {/* Tags */}
                  {cluster.tags.length > 0 && (
                    <Box sx={{ mb: 2 }}>
                      {cluster.tags.map((tag) => (
                        <Chip key={tag} label={tag} size="small" sx={{ mr: 0.5, mb: 0.5 }} />
                      ))}
                    </Box>
                  )}

                  {/* Test Result */}
                  {testResult && (
                    <Alert 
                      severity={testResult.success ? 'success' : 'error'} 
                      sx={{ mb: 2 }}
                    >
                      {testResult.message}
                    </Alert>
                  )}

                  {/* Last Connected */}
                  {cluster.lastConnected && (
                    <Typography variant="caption" color="text.secondary">
                      Last connected: {new Date(cluster.lastConnected).toLocaleString()}
                    </Typography>
                  )}
                </CardContent>

                {/* Actions */}
                <Box sx={{ p: 2, pt: 0, display: 'flex', justifyContent: 'space-between' }}>
                  <Box>
                    <Tooltip title="Test Connection">
                      <IconButton
                        onClick={() => handleTestConnection(cluster.id)}
                        disabled={testConnectionMutation.isLoading}
                      >
                        <TestIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="View Details">
                      <IconButton onClick={() => setSelectedCluster(cluster)}>
                        <ViewIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>
                  <Box>
                    <Tooltip title="Edit">
                      <IconButton
                        onClick={() => {
                          setSelectedCluster(cluster);
                          setIsEditDialogOpen(true);
                        }}
                      >
                        <EditIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete">
                      <IconButton
                        onClick={() => {
                          setSelectedCluster(cluster);
                          setIsDeleteDialogOpen(true);
                        }}
                        color="error"
                      >
                        <DeleteIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>
                </Box>
              </Card>
            </Grid>
          );
        })}
      </Grid>

      {/* Empty State */}
      {clusters.length === 0 && (
        <Box sx={{ textAlign: 'center', mt: 8 }}>
          <CloudIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
          <Typography variant="h6" color="text.secondary" gutterBottom>
            No clusters configured
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Add your first Kubernetes cluster to start managing security scans and deployments.
          </Typography>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setIsCreateDialogOpen(true)}
          >
            Add Your First Cluster
          </Button>
        </Box>
      )}

      {/* Create/Edit Cluster Dialog */}
      <ClusterDialog
        open={isCreateDialogOpen || isEditDialogOpen}
        onClose={() => {
          setIsCreateDialogOpen(false);
          setIsEditDialogOpen(false);
          setSelectedCluster(null);
        }}
        cluster={isEditDialogOpen ? selectedCluster : null}
        onSave={(clusterData) => {
          if (isEditDialogOpen && selectedCluster) {
            updateClusterMutation.mutate({ id: selectedCluster.id, data: clusterData });
          } else {
            createClusterMutation.mutate(clusterData as any);
          }
        }}
        isLoading={createClusterMutation.isLoading || updateClusterMutation.isLoading}
      />

      {/* Delete Confirmation Dialog */}
      <Dialog open={isDeleteDialogOpen} onClose={() => setIsDeleteDialogOpen(false)}>
        <DialogTitle>Delete Cluster</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete the cluster "{selectedCluster?.name}"? 
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setIsDeleteDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={handleDeleteCluster}
            color="error"
            disabled={deleteClusterMutation.isLoading}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Floating Action Button for Mobile */}
      <Fab
        color="primary"
        aria-label="add cluster"
        sx={{
          position: 'fixed',
          bottom: 16,
          right: 16,
          display: { xs: 'flex', md: 'none' },
        }}
        onClick={() => setIsCreateDialogOpen(true)}
      >
        <AddIcon />
      </Fab>
    </Box>
  );
};

// Cluster Dialog Component
interface ClusterDialogProps {
  open: boolean;
  onClose: () => void;
  cluster: ClusterConfig | null;
  onSave: (cluster: Partial<ClusterConfig>) => void;
  isLoading: boolean;
}

const ClusterDialog: React.FC<ClusterDialogProps> = ({
  open,
  onClose,
  cluster,
  onSave,
  isLoading,
}) => {
  const [formData, setFormData] = useState<Partial<ClusterConfig>>({
    name: '',
    description: '',
    endpoint: '',
    authentication: {
      type: 'certificate',
    },
    namespace: '',
    tags: [],
    provider: 'on-premise',
  });

  useEffect(() => {
    if (cluster) {
      setFormData(cluster);
    } else {
      setFormData({
        name: '',
        description: '',
        endpoint: '',
        authentication: {
          type: 'certificate',
        },
        namespace: '',
        tags: [],
        provider: 'on-premise',
      });
    }
  }, [cluster, open]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave(formData);
  };

  const handleInputChange = (field: string, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleAuthChange = (field: string, value: any) => {
    setFormData(prev => ({
      ...prev,
      authentication: { ...prev.authentication!, [field]: value },
    }));
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <form onSubmit={handleSubmit}>
        <DialogTitle>
          {cluster ? 'Edit Cluster' : 'Add New Cluster'}
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Cluster Name"
                value={formData.name}
                onChange={(e) => handleInputChange('name', e.target.value)}
                required
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Provider</InputLabel>
                <Select
                  value={formData.provider}
                  onChange={(e) => handleInputChange('provider', e.target.value)}
                >
                  <MenuItem value="aws">AWS EKS</MenuItem>
                  <MenuItem value="gcp">Google GKE</MenuItem>
                  <MenuItem value="azure">Azure AKS</MenuItem>
                  <MenuItem value="on-premise">On-Premise</MenuItem>
                  <MenuItem value="other">Other</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Description"
                value={formData.description}
                onChange={(e) => handleInputChange('description', e.target.value)}
                multiline
                rows={2}
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="API Server Endpoint"
                value={formData.endpoint}
                onChange={(e) => handleInputChange('endpoint', e.target.value)}
                placeholder="https://kubernetes.example.com:6443"
                required
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Authentication Type</InputLabel>
                <Select
                  value={formData.authentication?.type}
                  onChange={(e) => handleAuthChange('type', e.target.value)}
                >
                  <MenuItem value="certificate">Certificate</MenuItem>
                  <MenuItem value="token">Token</MenuItem>
                  <MenuItem value="serviceAccount">Service Account</MenuItem>
                  <MenuItem value="kubeconfig">Kubeconfig</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Default Namespace"
                value={formData.namespace}
                onChange={(e) => handleInputChange('namespace', e.target.value)}
                placeholder="default"
              />
            </Grid>

            {/* Authentication Fields */}
            {formData.authentication?.type === 'certificate' && (
              <>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Client Certificate"
                    value={formData.authentication.certificate || ''}
                    onChange={(e) => handleAuthChange('certificate', e.target.value)}
                    multiline
                    rows={4}
                    placeholder="-----BEGIN CERTIFICATE-----"
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Client Private Key"
                    value={formData.authentication.privateKey || ''}
                    onChange={(e) => handleAuthChange('privateKey', e.target.value)}
                    multiline
                    rows={4}
                    placeholder="-----BEGIN PRIVATE KEY-----"
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="CA Certificate"
                    value={formData.authentication.caCertificate || ''}
                    onChange={(e) => handleAuthChange('caCertificate', e.target.value)}
                    multiline
                    rows={4}
                    placeholder="-----BEGIN CERTIFICATE-----"
                  />
                </Grid>
              </>
            )}

            {formData.authentication?.type === 'token' && (
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Bearer Token"
                  value={formData.authentication.token || ''}
                  onChange={(e) => handleAuthChange('token', e.target.value)}
                  type="password"
                />
              </Grid>
            )}

            {formData.authentication?.type === 'kubeconfig' && (
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Kubeconfig Content"
                  value={formData.authentication.kubeconfig || ''}
                  onChange={(e) => handleAuthChange('kubeconfig', e.target.value)}
                  multiline
                  rows={8}
                  placeholder="apiVersion: v1..."
                />
              </Grid>
            )}

            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Tags (comma-separated)"
                value={formData.tags?.join(', ') || ''}
                onChange={(e) => handleInputChange('tags', e.target.value.split(',').map(t => t.trim()).filter(t => t))}
                placeholder="production, us-east-1, critical"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="contained" disabled={isLoading}>
            {cluster ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
};

export default ClustersPage;
