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
  Tabs,
  Tab,
  Badge,
  Switch,
  FormControlLabel,
  Divider,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
  Storage as StorageIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Sync as SyncIcon,
  Security as SecurityIcon,
  CloudUpload as UploadIcon,
  BugReport as VulnIcon,
  Schedule as ScheduleIcon,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { repositoryApi } from '../../services/repositoryApi';
import { ImageRepository, ChartRepository, VulnerabilityStats } from '../../types';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => (
  <div hidden={value !== index}>
    {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
  </div>
);

const RepositoriesPage: React.FC = () => {
  const [tabValue, setTabValue] = useState(0);
  const [selectedRepository, setSelectedRepository] = useState<ImageRepository | ChartRepository | null>(null);
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false);
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);
  const [repositoryType, setRepositoryType] = useState<'image' | 'chart'>('image');
  const queryClient = useQueryClient();

  // Fetch repositories
  const { data: imageRepositories = [], isLoading: imageLoading } = useQuery(
    'image-repositories',
    repositoryApi.getImageRepositories,
    { refetchInterval: 30000 }
  );

  const { data: chartRepositories = [], isLoading: chartLoading } = useQuery(
    'chart-repositories',
    repositoryApi.getChartRepositories,
    { refetchInterval: 30000 }
  );

  // Fetch repository stats
  const { data: repoStats } = useQuery(
    'repository-stats',
    repositoryApi.getRepositoryStats,
    { refetchInterval: 60000 }
  );

  // Mutations
  const createImageRepoMutation = useMutation(repositoryApi.createImageRepository, {
    onSuccess: () => {
      queryClient.invalidateQueries('image-repositories');
      setIsCreateDialogOpen(false);
    },
  });

  const createChartRepoMutation = useMutation(repositoryApi.createChartRepository, {
    onSuccess: () => {
      queryClient.invalidateQueries('chart-repositories');
      setIsCreateDialogOpen(false);
    },
  });

  const updateImageRepoMutation = useMutation(
    ({ id, data }: { id: string; data: Partial<ImageRepository> }) =>
      repositoryApi.updateImageRepository(id, data),
    {
      onSuccess: () => {
        queryClient.invalidateQueries('image-repositories');
        setIsEditDialogOpen(false);
        setSelectedRepository(null);
      },
    }
  );

  const updateChartRepoMutation = useMutation(
    ({ id, data }: { id: string; data: Partial<ChartRepository> }) =>
      repositoryApi.updateChartRepository(id, data),
    {
      onSuccess: () => {
        queryClient.invalidateQueries('chart-repositories');
        setIsEditDialogOpen(false);
        setSelectedRepository(null);
      },
    }
  );

  const deleteImageRepoMutation = useMutation(repositoryApi.deleteImageRepository, {
    onSuccess: () => {
      queryClient.invalidateQueries('image-repositories');
      setIsDeleteDialogOpen(false);
      setSelectedRepository(null);
    },
  });

  const deleteChartRepoMutation = useMutation(repositoryApi.deleteChartRepository, {
    onSuccess: () => {
      queryClient.invalidateQueries('chart-repositories');
      setIsDeleteDialogOpen(false);
      setSelectedRepository(null);
    },
  });

  const syncImageRepoMutation = useMutation(repositoryApi.syncImageRepository);
  const syncChartRepoMutation = useMutation(repositoryApi.syncChartRepository);

  const getRepositoryTypeIcon = (type: string) => {
    switch (type) {
      case 'docker':
      case 'harbor':
      case 'ecr':
      case 'gcr':
      case 'acr':
      case 'quay':
        return <StorageIcon />;
      case 'helm':
      case 'oci':
        return <StorageIcon />;
      default:
        return <StorageIcon />;
    }
  };

  const getVulnerabilityColor = (stats?: VulnerabilityStats) => {
    if (!stats || stats.total === 0) return 'default';
    if (stats.critical > 0) return 'error';
    if (stats.high > 0) return 'warning';
    if (stats.medium > 0) return 'info';
    return 'success';
  };

  const handleSync = (repository: ImageRepository | ChartRepository, type: 'image' | 'chart') => {
    if (type === 'image') {
      syncImageRepoMutation.mutate(repository.id);
    } else {
      syncChartRepoMutation.mutate(repository.id);
    }
  };

  const handleDelete = () => {
    if (!selectedRepository) return;
    
    if (tabValue === 0) {
      deleteImageRepoMutation.mutate(selectedRepository.id);
    } else {
      deleteChartRepoMutation.mutate(selectedRepository.id);
    }
  };

  const isLoading = imageLoading || chartLoading;

  if (isLoading) {
    return (
      <Box sx={{ width: '100%', mt: 2 }}>
        <LinearProgress />
        <Typography variant="h6" sx={{ mt: 2, textAlign: 'center' }}>
          Loading repositories...
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" component="h1">
          Repository Management
        </Typography>
        <Box>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => {
              queryClient.invalidateQueries('image-repositories');
              queryClient.invalidateQueries('chart-repositories');
            }}
            sx={{ mr: 2 }}
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => {
              setRepositoryType(tabValue === 0 ? 'image' : 'chart');
              setIsCreateDialogOpen(true);
            }}
          >
            Add Repository
          </Button>
        </Box>
      </Box>

      {/* Stats Cards */}
      {repoStats && (
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Total Repositories
                </Typography>
                <Typography variant="h4">
                  {repoStats.totalRepositories}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Total Images
                </Typography>
                <Typography variant="h4">
                  {repoStats.totalImages}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Total Charts
                </Typography>
                <Typography variant="h4">
                  {repoStats.totalCharts}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Critical Vulnerabilities
                </Typography>
                <Typography variant="h4" color="error">
                  {repoStats.criticalVulnerabilities}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={tabValue} onChange={(_, newValue) => setTabValue(newValue)}>
          <Tab
            label={
              <Badge badgeContent={imageRepositories.length} color="primary">
                Image Repositories
              </Badge>
            }
          />
          <Tab
            label={
              <Badge badgeContent={chartRepositories.length} color="primary">
                Chart Repositories
              </Badge>
            }
          />
        </Tabs>
      </Box>

      {/* Image Repositories Tab */}
      <TabPanel value={tabValue} index={0}>
        <Grid container spacing={3}>
          {imageRepositories.map((repo) => (
            <Grid item xs={12} md={6} lg={4} key={repo.id}>
              <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                <CardContent sx={{ flexGrow: 1 }}>
                  {/* Repository Header */}
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      {getRepositoryTypeIcon(repo.type)}
                      <Box sx={{ ml: 1 }}>
                        <Typography variant="h6" component="h2">
                          {repo.name}
                        </Typography>
                        <Chip label={repo.type.toUpperCase()} size="small" />
                      </Box>
                    </Box>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      {repo.isActive ? (
                        <CheckCircleIcon color="success" />
                      ) : (
                        <ErrorIcon color="error" />
                      )}
                    </Box>
                  </Box>

                  {/* Repository Details */}
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    {repo.url}
                  </Typography>

                  {/* Stats */}
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', my: 2 }}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h6">{repo.imageCount || 0}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        Images
                      </Typography>
                    </Box>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography 
                        variant="h6" 
                        color={getVulnerabilityColor(repo.vulnerabilityStats)}
                      >
                        {repo.vulnerabilityStats?.total || 0}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Vulnerabilities
                      </Typography>
                    </Box>
                  </Box>

                  {/* Vulnerability Breakdown */}
                  {repo.vulnerabilityStats && repo.vulnerabilityStats.total > 0 && (
                    <Box sx={{ mb: 2 }}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                        <Chip label={`Critical: ${repo.vulnerabilityStats.critical}`} size="small" color="error" />
                        <Chip label={`High: ${repo.vulnerabilityStats.high}`} size="small" color="warning" />
                        <Chip label={`Medium: ${repo.vulnerabilityStats.medium}`} size="small" color="info" />
                        <Chip label={`Low: ${repo.vulnerabilityStats.low}`} size="small" color="success" />
                      </Box>
                    </Box>
                  )}

                  {/* Settings */}
                  <Box sx={{ mb: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                      <SecurityIcon sx={{ mr: 1, fontSize: 16 }} />
                      <Typography variant="caption">
                        Scan on Push: {repo.scanOnPush ? 'Enabled' : 'Disabled'}
                      </Typography>
                    </Box>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <ScheduleIcon sx={{ mr: 1, fontSize: 16 }} />
                      <Typography variant="caption">
                        Auto Scan: {repo.autoScan ? 'Enabled' : 'Disabled'}
                      </Typography>
                    </Box>
                  </Box>

                  {/* Last Sync */}
                  {repo.lastSync && (
                    <Typography variant="caption" color="text.secondary">
                      Last sync: {new Date(repo.lastSync).toLocaleString()}
                    </Typography>
                  )}
                </CardContent>

                {/* Actions */}
                <Box sx={{ p: 2, pt: 0, display: 'flex', justifyContent: 'space-between' }}>
                  <Box>
                    <Tooltip title="Sync Repository">
                      <IconButton
                        onClick={() => handleSync(repo, 'image')}
                        disabled={syncImageRepoMutation.isLoading}
                      >
                        <SyncIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>
                  <Box>
                    <Tooltip title="Edit">
                      <IconButton
                        onClick={() => {
                          setSelectedRepository(repo);
                          setRepositoryType('image');
                          setIsEditDialogOpen(true);
                        }}
                      >
                        <EditIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete">
                      <IconButton
                        onClick={() => {
                          setSelectedRepository(repo);
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
          ))}
        </Grid>

        {/* Empty State for Image Repositories */}
        {imageRepositories.length === 0 && (
          <Box sx={{ textAlign: 'center', mt: 8 }}>
            <StorageIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No image repositories configured
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Add your first image repository to start scanning container images for vulnerabilities.
            </Typography>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={() => {
                setRepositoryType('image');
                setIsCreateDialogOpen(true);
              }}
            >
              Add Image Repository
            </Button>
          </Box>
        )}
      </TabPanel>

      {/* Chart Repositories Tab */}
      <TabPanel value={tabValue} index={1}>
        <Grid container spacing={3}>
          {chartRepositories.map((repo) => (
            <Grid item xs={12} md={6} lg={4} key={repo.id}>
              <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                <CardContent sx={{ flexGrow: 1 }}>
                  {/* Repository Header */}
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      {getRepositoryTypeIcon(repo.type)}
                      <Box sx={{ ml: 1 }}>
                        <Typography variant="h6" component="h2">
                          {repo.name}
                        </Typography>
                        <Chip label={repo.type.toUpperCase()} size="small" />
                      </Box>
                    </Box>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      {repo.isActive ? (
                        <CheckCircleIcon color="success" />
                      ) : (
                        <ErrorIcon color="error" />
                      )}
                    </Box>
                  </Box>

                  {/* Repository Details */}
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    {repo.url}
                  </Typography>

                  {/* Stats */}
                  <Box sx={{ display: 'flex', justifyContent: 'center', my: 2 }}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h6">{repo.chartCount || 0}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        Charts
                      </Typography>
                    </Box>
                  </Box>

                  {/* Last Sync */}
                  {repo.lastSync && (
                    <Typography variant="caption" color="text.secondary">
                      Last sync: {new Date(repo.lastSync).toLocaleString()}
                    </Typography>
                  )}
                </CardContent>

                {/* Actions */}
                <Box sx={{ p: 2, pt: 0, display: 'flex', justifyContent: 'space-between' }}>
                  <Box>
                    <Tooltip title="Sync Repository">
                      <IconButton
                        onClick={() => handleSync(repo, 'chart')}
                        disabled={syncChartRepoMutation.isLoading}
                      >
                        <SyncIcon />
                      </IconButton>
                    </Tooltip>
                  </Box>
                  <Box>
                    <Tooltip title="Edit">
                      <IconButton
                        onClick={() => {
                          setSelectedRepository(repo);
                          setRepositoryType('chart');
                          setIsEditDialogOpen(true);
                        }}
                      >
                        <EditIcon />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete">
                      <IconButton
                        onClick={() => {
                          setSelectedRepository(repo);
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
          ))}
        </Grid>

        {/* Empty State for Chart Repositories */}
        {chartRepositories.length === 0 && (
          <Box sx={{ textAlign: 'center', mt: 8 }}>
            <StorageIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              No chart repositories configured
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              Add your first chart repository to start managing Helm charts and deployments.
            </Typography>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={() => {
                setRepositoryType('chart');
                setIsCreateDialogOpen(true);
              }}
            >
              Add Chart Repository
            </Button>
          </Box>
        )}
      </TabPanel>

      {/* Create/Edit Repository Dialog */}
      <RepositoryDialog
        open={isCreateDialogOpen || isEditDialogOpen}
        onClose={() => {
          setIsCreateDialogOpen(false);
          setIsEditDialogOpen(false);
          setSelectedRepository(null);
        }}
        repository={isEditDialogOpen ? selectedRepository : null}
        repositoryType={repositoryType}
        onSave={(repoData) => {
          if (isEditDialogOpen && selectedRepository) {
            if (repositoryType === 'image') {
              updateImageRepoMutation.mutate({ id: selectedRepository.id, data: repoData });
            } else {
              updateChartRepoMutation.mutate({ id: selectedRepository.id, data: repoData });
            }
          } else {
            if (repositoryType === 'image') {
              createImageRepoMutation.mutate(repoData as any);
            } else {
              createChartRepoMutation.mutate(repoData as any);
            }
          }
        }}
        isLoading={
          createImageRepoMutation.isLoading ||
          createChartRepoMutation.isLoading ||
          updateImageRepoMutation.isLoading ||
          updateChartRepoMutation.isLoading
        }
      />

      {/* Delete Confirmation Dialog */}
      <Dialog open={isDeleteDialogOpen} onClose={() => setIsDeleteDialogOpen(false)}>
        <DialogTitle>Delete Repository</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete the repository "{selectedRepository?.name}"? 
            This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setIsDeleteDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={handleDelete}
            color="error"
            disabled={deleteImageRepoMutation.isLoading || deleteChartRepoMutation.isLoading}
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

// Repository Dialog Component (simplified for brevity)
interface RepositoryDialogProps {
  open: boolean;
  onClose: () => void;
  repository: ImageRepository | ChartRepository | null;
  repositoryType: 'image' | 'chart';
  onSave: (repository: any) => void;
  isLoading: boolean;
}

const RepositoryDialog: React.FC<RepositoryDialogProps> = ({
  open,
  onClose,
  repository,
  repositoryType,
  onSave,
  isLoading,
}) => {
  const [formData, setFormData] = useState<any>({
    name: '',
    url: '',
    type: repositoryType === 'image' ? 'docker' : 'helm',
    authentication: {
      type: 'none',
    },
    isActive: true,
  });

  useEffect(() => {
    if (repository) {
      setFormData(repository);
    } else {
      setFormData({
        name: '',
        url: '',
        type: repositoryType === 'image' ? 'docker' : 'helm',
        authentication: {
          type: 'none',
        },
        isActive: true,
        ...(repositoryType === 'image' && {
          scanOnPush: false,
          autoScan: false,
        }),
      });
    }
  }, [repository, repositoryType, open]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave(formData);
  };

  const handleInputChange = (field: string, value: any) => {
    setFormData((prev: any) => ({ ...prev, [field]: value }));
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <form onSubmit={handleSubmit}>
        <DialogTitle>
          {repository ? 'Edit' : 'Add'} {repositoryType === 'image' ? 'Image' : 'Chart'} Repository
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Repository Name"
                value={formData.name}
                onChange={(e) => handleInputChange('name', e.target.value)}
                required
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Type</InputLabel>
                <Select
                  value={formData.type}
                  onChange={(e) => handleInputChange('type', e.target.value)}
                >
                  {repositoryType === 'image' ? (
                    <>
                      <MenuItem value="docker">Docker Hub</MenuItem>
                      <MenuItem value="harbor">Harbor</MenuItem>
                      <MenuItem value="ecr">AWS ECR</MenuItem>
                      <MenuItem value="gcr">Google GCR</MenuItem>
                      <MenuItem value="acr">Azure ACR</MenuItem>
                      <MenuItem value="quay">Quay.io</MenuItem>
                    </>
                  ) : (
                    <>
                      <MenuItem value="helm">Helm</MenuItem>
                      <MenuItem value="oci">OCI</MenuItem>
                    </>
                  )}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Repository URL"
                value={formData.url}
                onChange={(e) => handleInputChange('url', e.target.value)}
                placeholder={repositoryType === 'image' ? 'https://registry.example.com' : 'https://charts.example.com'}
                required
              />
            </Grid>

            {repositoryType === 'image' && (
              <>
                <Grid item xs={12}>
                  <Divider sx={{ my: 2 }} />
                  <Typography variant="h6" gutterBottom>
                    Scanning Options
                  </Typography>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={formData.scanOnPush || false}
                        onChange={(e) => handleInputChange('scanOnPush', e.target.checked)}
                      />
                    }
                    label="Scan on Push"
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={formData.autoScan || false}
                        onChange={(e) => handleInputChange('autoScan', e.target.checked)}
                      />
                    }
                    label="Auto Scan"
                  />
                </Grid>
              </>
            )}

            <Grid item xs={12}>
              <FormControlLabel
                control={
                  <Switch
                    checked={formData.isActive}
                    onChange={(e) => handleInputChange('isActive', e.target.checked)}
                  />
                }
                label="Active"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="contained" disabled={isLoading}>
            {repository ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
};

export default RepositoriesPage;
