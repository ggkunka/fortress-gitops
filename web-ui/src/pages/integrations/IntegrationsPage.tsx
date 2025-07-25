import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
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
  Grid,
  Alert,
  Switch,
  FormControlLabel,
  Tabs,
  Tab,
  Avatar,
  IconButton,
  Menu,
  Tooltip,
  CircularProgress,
} from '@mui/material';
import {
  Add as AddIcon,
  Settings as SettingsIcon,
  MoreVert as MoreVertIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Sync as SyncIcon,
  Cloud as CloudIcon,
  Security as SecurityIcon,
  Storage as StorageIcon,
  Assessment as AssessmentIcon,
} from '@mui/icons-material';
import { DataGrid, GridColDef, GridActionsCellItem } from '@mui/x-data-grid';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { integrationsApi, Integration, CreateIntegrationRequest } from '../../services/integrationsApi';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`integration-tabpanel-${index}`}
      aria-labelledby={`integration-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

export const IntegrationsPage: React.FC = () => {
  const [tabValue, setTabValue] = useState(0);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedIntegrationType, setSelectedIntegrationType] = useState('');
  const [selectedProvider, setSelectedProvider] = useState('');
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null);
  const [selectedIntegration, setSelectedIntegration] = useState<Integration | null>(null);

  const queryClient = useQueryClient();

  // Fetch integrations with API calls
  const { data: integrationResponse, isLoading } = useQuery({
    queryKey: ['integrations'],
    queryFn: () => integrationsApi.getIntegrations({
      page: 1,
      limit: 100,
    }),
    refetchInterval: 30000,
  });

  const integrations = integrationResponse?.integrations || [];

  // Fetch integration statistics
  const { data: integrationStats } = useQuery({
    queryKey: ['integration-stats'],
    queryFn: () => integrationsApi.getIntegrationStats(),
    refetchInterval: 60000,
  });

  // Fetch integration providers
  const { data: providers = [] } = useQuery({
    queryKey: ['integration-providers'],
    queryFn: () => integrationsApi.getIntegrationProviders(),
  });

  // Mutations for integration actions
  const createIntegrationMutation = useMutation({
    mutationFn: (integrationData: CreateIntegrationRequest) => 
      integrationsApi.createIntegration(integrationData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
      queryClient.invalidateQueries({ queryKey: ['integration-stats'] });
      setCreateDialogOpen(false);
    },
  });

  const toggleIntegrationMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      integrationsApi.toggleIntegration(id, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
      queryClient.invalidateQueries({ queryKey: ['integration-stats'] });
    },
  });

  const syncIntegrationMutation = useMutation({
    mutationFn: (id: string) => integrationsApi.syncIntegration(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
    },
  });

  const deleteIntegrationMutation = useMutation({
    mutationFn: (id: string) => integrationsApi.deleteIntegration(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
      queryClient.invalidateQueries({ queryKey: ['integration-stats'] });
      handleMenuClose();
    },
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'connected': return 'success';
      case 'disconnected': return 'default';
      case 'error': return 'error';
      case 'testing': return 'warning';
      default: return 'default';
    }
  };

  const getHealthIcon = (health: string) => {
    switch (health) {
      case 'healthy': return <CheckIcon color="success" />;
      case 'warning': return <WarningIcon color="warning" />;
      case 'error': return <ErrorIcon color="error" />;
      default: return <WarningIcon />;
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'siem': return <SecurityIcon />;
      case 'cloud_security': return <CloudIcon />;
      case 'threat_intelligence': return <AssessmentIcon />;
      case 'vulnerability_management': return <StorageIcon />;
      case 'ticketing': return <SettingsIcon />;
      default: return <SettingsIcon />;
    }
  };

  // Group providers by type for the create dialog
  const getProvidersByType = (type: string) => {
    return providers.filter(provider => provider.type === type);
  };

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, integration: Integration) => {
    setMenuAnchor(event.currentTarget);
    setSelectedIntegration(integration);
  };

  const handleMenuClose = () => {
    setMenuAnchor(null);
    setSelectedIntegration(null);
  };

  const columns: GridColDef[] = [
    {
      field: 'name',
      headerName: 'Integration',
      flex: 1,
      minWidth: 200,
      renderCell: (params) => (
        <Box display="flex" alignItems="center">
          <Avatar
            sx={{ width: 32, height: 32, mr: 2, bgcolor: 'primary.light' }}
          >
            {getTypeIcon(params.row.type)}
          </Avatar>
          <Box>
            <Typography variant="body2" fontWeight="medium">
              {params.value}
            </Typography>
            <Typography variant="caption" color="textSecondary">
              {params.row.provider} • {params.row.type.replace('_', ' ')}
            </Typography>
          </Box>
        </Box>
      ),
    },
    {
      field: 'status',
      headerName: 'Status',
      width: 120,
      renderCell: (params) => (
        <Chip
          label={params.value}
          size="small"
          color={getStatusColor(params.value) as any}
          variant="outlined"
          sx={{ textTransform: 'capitalize' }}
        />
      ),
    },
    {
      field: 'health',
      headerName: 'Health',
      width: 100,
      align: 'center',
      headerAlign: 'center',
      renderCell: (params) => (
        <Tooltip title={params.value.message || params.value.status}>
          {getHealthIcon(params.value.status)}
        </Tooltip>
      ),
    },
    {
      field: 'enabled',
      headerName: 'Enabled',
      width: 100,
      renderCell: (params) => (
        <Switch
          checked={params.value}
          onChange={(e) => toggleIntegration.mutate({ 
            id: params.row.id, 
            enabled: e.target.checked 
          })}
          disabled={toggleIntegration.isPending}
        />
      ),
    },
    {
      field: 'last_sync',
      headerName: 'Last Sync',
      width: 150,
      renderCell: (params) => (
        <Typography variant="body2">
          {params.value ? new Date(params.value).toLocaleString() : 'Never'}
        </Typography>
      ),
    },
    {
      field: 'sync_frequency',
      headerName: 'Frequency',
      width: 100,
      renderCell: (params) => (
        <Typography variant="body2">
          {params.value}m
        </Typography>
      ),
    },
    {
      field: 'actions',
      type: 'actions',
      headerName: 'Actions',
      width: 120,
      getActions: (params) => [
        <GridActionsCellItem
          icon={<SyncIcon />}
          label="Sync Now"
          onClick={() => console.log('Sync integration', params.row.id)}
        />,
        <GridActionsCellItem
          icon={<MoreVertIcon />}
          label="More"
          onClick={(event) => handleMenuOpen(event, params.row)}
        />,
      ],
    },
  ];

  const filterIntegrationsByType = (type?: string) => {
    if (!type) return integrations;
    return integrations.filter(integration => integration.type === type);
  };

  return (
    <Box>
      {/* Header */}
      <Box display="flex" justifyContent="between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          Integrations
        </Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setCreateDialogOpen(true)}
        >
          Add Integration
        </Button>
      </Box>

      {/* Stats Cards */}
      <Grid container spacing={2} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Integrations
              </Typography>
              <Typography variant="h5">
                {integrationStats?.total_integrations || integrations.length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Connected
              </Typography>
              <Typography variant="h5" color="success.main">
                {integrationStats?.connected_integrations || integrations.filter(i => i.status === 'connected').length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Enabled
              </Typography>
              <Typography variant="h5" color="primary.main">
                {integrationStats?.enabled_integrations || integrations.filter(i => i.enabled).length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Errors
              </Typography>
              <Typography variant="h5" color="error.main">
                {integrationStats?.failed_integrations || integrations.filter(i => i.status === 'error').length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs for Integration Types */}
      <Card>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs value={tabValue} onChange={(e, newValue) => setTabValue(newValue)}>
            <Tab label="All" />
            <Tab label="SIEM" />
            <Tab label="Cloud Security" />
            <Tab label="Threat Intel" />
            <Tab label="Vuln Management" />
            <Tab label="Ticketing" />
          </Tabs>
        </Box>

        <TabPanel value={tabValue} index={0}>
          <DataGrid
            rows={integrations}
            columns={columns}
            loading={isLoading}
            autoHeight
            disableRowSelectionOnClick
            initialState={{
              pagination: {
                paginationModel: { page: 0, pageSize: 10 },
              },
            }}
            pageSizeOptions={[10, 25, 50]}
          />
        </TabPanel>

        <TabPanel value={tabValue} index={1}>
          <DataGrid
            rows={filterIntegrationsByType('siem')}
            columns={columns}
            loading={isLoading}
            autoHeight
            disableRowSelectionOnClick
            initialState={{
              pagination: {
                paginationModel: { page: 0, pageSize: 10 },
              },
            }}
            pageSizeOptions={[10, 25, 50]}
          />
        </TabPanel>

        <TabPanel value={tabValue} index={2}>
          <DataGrid
            rows={filterIntegrationsByType('cloud_security')}
            columns={columns}
            loading={isLoading}
            autoHeight
            disableRowSelectionOnClick
            initialState={{
              pagination: {
                paginationModel: { page: 0, pageSize: 10 },
              },
            }}
            pageSizeOptions={[10, 25, 50]}
          />
        </TabPanel>

        <TabPanel value={tabValue} index={3}>
          <DataGrid
            rows={filterIntegrationsByType('threat_intelligence')}
            columns={columns}
            loading={isLoading}
            autoHeight
            disableRowSelectionOnClick
            initialState={{
              pagination: {
                paginationModel: { page: 0, pageSize: 10 },
              },
            }}
            pageSizeOptions={[10, 25, 50]}
          />
        </TabPanel>

        <TabPanel value={tabValue} index={4}>
          <DataGrid
            rows={filterIntegrationsByType('vulnerability_management')}
            columns={columns}
            loading={isLoading}
            autoHeight
            disableRowSelectionOnClick
            initialState={{
              pagination: {
                paginationModel: { page: 0, pageSize: 10 },
              },
            }}
            pageSizeOptions={[10, 25, 50]}
          />
        </TabPanel>

        <TabPanel value={tabValue} index={5}>
          <DataGrid
            rows={filterIntegrationsByType('ticketing')}
            columns={columns}
            loading={isLoading}
            autoHeight
            disableRowSelectionOnClick
            initialState={{
              pagination: {
                paginationModel: { page: 0, pageSize: 10 },
              },
            }}
            pageSizeOptions={[10, 25, 50]}
          />
        </TabPanel>
      </Card>

      {/* Context Menu */}
      <Menu
        anchorEl={menuAnchor}
        open={Boolean(menuAnchor)}
        onClose={handleMenuClose}
      >
        <MenuItem onClick={handleMenuClose}>
          <SettingsIcon sx={{ mr: 1 }} /> Configure
        </MenuItem>
        <MenuItem onClick={handleMenuClose}>
          <SyncIcon sx={{ mr: 1 }} /> Test Connection
        </MenuItem>
        <MenuItem onClick={handleMenuClose}>
          View Logs
        </MenuItem>
        <MenuItem onClick={handleMenuClose} sx={{ color: 'error.main' }}>
          Delete Integration
        </MenuItem>
      </Menu>

      {/* Add Integration Dialog */}
      <Dialog
        open={createDialogOpen}
        onClose={() => setCreateDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Add New Integration</DialogTitle>
        <DialogContent>
          <Alert severity="info" sx={{ mb: 3 }}>
            Configure a new integration to connect with external security tools and services.
          </Alert>

          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth required>
                <InputLabel>Integration Type</InputLabel>
                <Select
                  value={selectedIntegrationType}
                  label="Integration Type"
                  onChange={(e) => {
                    setSelectedIntegrationType(e.target.value);
                    setSelectedProvider('');
                  }}
                >
                  <MenuItem value="siem">SIEM</MenuItem>
                  <MenuItem value="cloud_security">Cloud Security</MenuItem>
                  <MenuItem value="threat_intelligence">Threat Intelligence</MenuItem>
                  <MenuItem value="vulnerability_management">Vulnerability Management</MenuItem>
                  <MenuItem value="ticketing">Ticketing System</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth required disabled={!selectedIntegrationType}>
                <InputLabel>Provider</InputLabel>
                <Select
                  value={selectedProvider}
                  label="Provider"
                  onChange={(e) => setSelectedProvider(e.target.value)}
                >
                  {selectedIntegrationType && integrationProviders[selectedIntegrationType as keyof typeof integrationProviders]?.map((provider) => (
                    <MenuItem key={provider} value={provider}>
                      {provider.charAt(0).toUpperCase() + provider.slice(1).replace('_', ' ')}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Integration Name"
                placeholder="e.g., Production Splunk SIEM"
                required
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Endpoint URL"
                placeholder="https://your-service.company.com"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="API Key / Token"
                type="password"
                placeholder="Enter your API key or token"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Username"
                placeholder="Integration username (if required)"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>Sync Frequency</InputLabel>
                <Select
                  defaultValue={15}
                  label="Sync Frequency"
                >
                  <MenuItem value={5}>Every 5 minutes</MenuItem>
                  <MenuItem value={15}>Every 15 minutes</MenuItem>
                  <MenuItem value={30}>Every 30 minutes</MenuItem>
                  <MenuItem value={60}>Every hour</MenuItem>
                  <MenuItem value={240}>Every 4 hours</MenuItem>
                  <MenuItem value={1440}>Daily</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <FormControlLabel
                control={<Switch defaultChecked />}
                label="Enable integration after creation"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={() => setCreateDialogOpen(false)}
          >
            Test & Create Integration
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};