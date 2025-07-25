import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  Chip,
  IconButton,
  Menu,
  MenuItem,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  Grid,
  Alert,
} from '@mui/material';
import {
  Add as AddIcon,
  MoreVert as MoreVertIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  Search as SearchIcon,
} from '@mui/icons-material';
import { DataGrid, GridColDef, GridActionsCellItem } from '@mui/x-data-grid';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { scansApi, Scan, CreateScanRequest } from '../../services/scansApi';

export const ScansPage: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);

  const queryClient = useQueryClient();

  // Fetch scans with API calls
  const { data: scanResponse, isLoading } = useQuery({
    queryKey: ['scans', searchTerm, statusFilter, typeFilter],
    queryFn: () => scansApi.getScans({
      search: searchTerm || undefined,
      status: statusFilter !== 'all' ? statusFilter : undefined,
      type: typeFilter !== 'all' ? typeFilter : undefined,
      page: 1,
      limit: 100,
    }),
    refetchInterval: 10000, // Refresh every 10 seconds for real-time updates
  });

  const scans = scanResponse?.scans || [];

  // Fetch scan statistics
  const { data: scanStats } = useQuery({
    queryKey: ['scan-stats'],
    queryFn: () => scansApi.getScanStats(),
    refetchInterval: 30000,
  });

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, scan: Scan) => {
    setMenuAnchor(event.currentTarget);
    setSelectedScan(scan);
  };

  const handleMenuClose = () => {
    setMenuAnchor(null);
    setSelectedScan(null);
  };

  // Mutations for scan actions
  const createScanMutation = useMutation({
    mutationFn: (scanData: CreateScanRequest) => scansApi.createScan(scanData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['scan-stats'] });
      setCreateDialogOpen(false);
    },
  });

  const startScanMutation = useMutation({
    mutationFn: (scanId: string) => scansApi.startScan(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['scan-stats'] });
      handleMenuClose();
    },
  });

  const stopScanMutation = useMutation({
    mutationFn: (scanId: string) => scansApi.stopScan(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['scan-stats'] });
      handleMenuClose();
    },
  });

  const deleteScanMutation = useMutation({
    mutationFn: (scanId: string) => scansApi.deleteScan(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      queryClient.invalidateQueries({ queryKey: ['scan-stats'] });
      handleMenuClose();
    },
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'primary';
      case 'completed': return 'success';
      case 'failed': return 'error';
      case 'pending': return 'warning';
      case 'cancelled': return 'default';
      default: return 'default';
    }
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'network': return '#1976d2';
      case 'web': return '#388e3c';
      case 'infrastructure': return '#f57c00';
      case 'compliance': return '#7b1fa2';
      default: return '#666';
    }
  };

  const columns: GridColDef[] = [
    {
      field: 'name',
      headerName: 'Scan Name',
      flex: 1,
      minWidth: 200,
      renderCell: (params) => (
        <Box>
          <Typography variant="body2" fontWeight="medium">
            {params.value}
          </Typography>
          <Typography variant="caption" color="textSecondary">
            {params.row.target}
          </Typography>
        </Box>
      ),
    },
    {
      field: 'type',
      headerName: 'Type',
      width: 120,
      renderCell: (params) => (
        <Chip
          label={params.value}
          size="small"
          sx={{
            backgroundColor: getTypeColor(params.value),
            color: 'white',
            textTransform: 'capitalize',
          }}
        />
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
      field: 'progress',
      headerName: 'Progress',
      width: 100,
      renderCell: (params) => (
        <Box sx={{ width: '100%' }}>
          <Typography variant="caption">
            {params.value}%
          </Typography>
        </Box>
      ),
    },
    {
      field: 'vulnerabilities_found',
      headerName: 'Vulns Found',
      width: 100,
      align: 'center',
      headerAlign: 'center',
    },
    {
      field: 'severity_counts',
      headerName: 'Severity Distribution',
      width: 200,
      renderCell: (params) => (
        <Box display="flex" gap={0.5}>
          {params.value.critical > 0 && (
            <Chip label={`C:${params.value.critical}`} size="small" className="severity-critical" />
          )}
          {params.value.high > 0 && (
            <Chip label={`H:${params.value.high}`} size="small" className="severity-high" />
          )}
          {params.value.medium > 0 && (
            <Chip label={`M:${params.value.medium}`} size="small" className="severity-medium" />
          )}
          {params.value.low > 0 && (
            <Chip label={`L:${params.value.low}`} size="small" className="severity-low" />
          )}
        </Box>
      ),
    },
    {
      field: 'created_at',
      headerName: 'Created',
      width: 150,
      renderCell: (params) => (
        <Typography variant="body2">
          {new Date(params.value).toLocaleString()}
        </Typography>
      ),
    },
    {
      field: 'actions',
      type: 'actions',
      headerName: 'Actions',
      width: 100,
      getActions: (params) => [
        <GridActionsCellItem
          icon={<MoreVertIcon />}
          label="More"
          onClick={(event) => handleMenuOpen(event, params.row)}
        />,
      ],
    },
  ];

  return (
    <Box>
      {/* Header */}
      <Box display="flex" justifyContent="between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          Security Scans
        </Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setCreateDialogOpen(true)}
        >
          New Scan
        </Button>
      </Box>

      {/* Stats Cards */}
      <Grid container spacing={2} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Scans
              </Typography>
              <Typography variant="h5">
                {scanStats?.total || scans.length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Running
              </Typography>
              <Typography variant="h5" color="primary">
                {scanStats?.running || scans.filter(s => s.status === 'running').length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Completed
              </Typography>
              <Typography variant="h5" color="success.main">
                {scanStats?.completed || scans.filter(s => s.status === 'completed').length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Failed
              </Typography>
              <Typography variant="h5" color="error.main">
                {scanStats?.failed || scans.filter(s => s.status === 'failed').length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} md={4}>
              <TextField
                fullWidth
                placeholder="Search scans..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                InputProps={{
                  startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
                }}
              />
            </Grid>
            <Grid item xs={12} md={3}>
              <FormControl fullWidth>
                <InputLabel>Status</InputLabel>
                <Select
                  value={statusFilter}
                  label="Status"
                  onChange={(e) => setStatusFilter(e.target.value)}
                >
                  <MenuItem value="all">All Statuses</MenuItem>
                  <MenuItem value="pending">Pending</MenuItem>
                  <MenuItem value="running">Running</MenuItem>
                  <MenuItem value="completed">Completed</MenuItem>
                  <MenuItem value="failed">Failed</MenuItem>
                  <MenuItem value="cancelled">Cancelled</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={3}>
              <FormControl fullWidth>
                <InputLabel>Type</InputLabel>
                <Select
                  value={typeFilter}
                  label="Type"
                  onChange={(e) => setTypeFilter(e.target.value)}
                >
                  <MenuItem value="all">All Types</MenuItem>
                  <MenuItem value="network">Network</MenuItem>
                  <MenuItem value="web">Web Application</MenuItem>
                  <MenuItem value="infrastructure">Infrastructure</MenuItem>
                  <MenuItem value="compliance">Compliance</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={2}>
              <Button
                fullWidth
                variant="outlined"
                startIcon={<RefreshIcon />}
                onClick={() => queryClient.invalidateQueries({ queryKey: ['scans'] })}
              >
                Refresh
              </Button>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Scans Table */}
      <Card>
        <DataGrid
          rows={scans}
          columns={columns}
          loading={isLoading}
          autoHeight
          checkboxSelection
          disableRowSelectionOnClick
          initialState={{
            pagination: {
              paginationModel: { page: 0, pageSize: 25 },
            },
          }}
          pageSizeOptions={[10, 25, 50, 100]}
        />
      </Card>

      {/* Context Menu */}
      <Menu
        anchorEl={menuAnchor}
        open={Boolean(menuAnchor)}
        onClose={handleMenuClose}
      >
        <MenuItem onClick={handleMenuClose}>
          <PlayIcon sx={{ mr: 1 }} /> Start Scan
        </MenuItem>
        <MenuItem onClick={handleMenuClose}>
          <StopIcon sx={{ mr: 1 }} /> Stop Scan
        </MenuItem>
        <MenuItem onClick={handleMenuClose}>
          View Details
        </MenuItem>
        <MenuItem onClick={handleMenuClose}>
          Download Report
        </MenuItem>
        <MenuItem onClick={handleMenuClose} sx={{ color: 'error.main' }}>
          Delete Scan
        </MenuItem>
      </Menu>

      {/* Create Scan Dialog */}
      <Dialog
        open={createDialogOpen}
        onClose={() => setCreateDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Create New Security Scan</DialogTitle>
        <DialogContent>
          <Alert severity="info" sx={{ mb: 2 }}>
            Configure your security scan parameters below. The scan will begin immediately after creation.
          </Alert>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Scan Name"
                placeholder="e.g., Production Network Scan"
                required
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth required>
                <InputLabel>Scan Type</InputLabel>
                <Select
                  label="Scan Type"
                  defaultValue=""
                >
                  <MenuItem value="network">Network Scan</MenuItem>
                  <MenuItem value="web">Web Application</MenuItem>
                  <MenuItem value="infrastructure">Infrastructure</MenuItem>
                  <MenuItem value="compliance">Compliance Check</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label="Target"
                placeholder="e.g., 192.168.1.0/24 or https://example.com"
                required
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Description"
                placeholder="Optional description of the scan"
                multiline
                rows={3}
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
            Create Scan
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};