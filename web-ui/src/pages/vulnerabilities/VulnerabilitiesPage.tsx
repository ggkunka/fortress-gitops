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
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
  Link,
  Tooltip,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Search as SearchIcon,
  FilterList as FilterIcon,
  GetApp as ExportIcon,
  BugReport as BugIcon,
  Security as SecurityIcon,
  Assignment as AssignmentIcon,
  OpenInNew as OpenInNewIcon,
} from '@mui/icons-material';
import { DataGrid, GridColDef, GridActionsCellItem } from '@mui/x-data-grid';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { vulnerabilitiesApi, Vulnerability, UpdateVulnerabilityRequest } from '../../services/vulnerabilitiesApi';

export const VulnerabilitiesPage: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [assetFilter, setAssetFilter] = useState<string>('');
  const [selectedVuln, setSelectedVuln] = useState<Vulnerability | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [filterMenuAnchor, setFilterMenuAnchor] = useState<null | HTMLElement>(null);

  const queryClient = useQueryClient();

  // Fetch vulnerabilities with API calls
  const { data: vulnResponse, isLoading } = useQuery({
    queryKey: ['vulnerabilities', searchTerm, severityFilter, statusFilter, assetFilter],
    queryFn: () => vulnerabilitiesApi.getVulnerabilities({
      search: searchTerm || undefined,
      severity: severityFilter !== 'all' ? [severityFilter] : undefined,
      status: statusFilter !== 'all' ? [statusFilter] : undefined,
      asset: assetFilter || undefined,
      page: 1,
      limit: 100,
    }),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  const vulnerabilities = vulnResponse?.vulnerabilities || [];

  // Fetch vulnerability statistics
  const { data: vulnStats } = useQuery({
    queryKey: ['vulnerability-stats'],
    queryFn: () => vulnerabilitiesApi.getVulnerabilityStats(),
    refetchInterval: 60000,
  });

  // Mutations for vulnerability actions
  const updateVulnerabilityMutation = useMutation({
    mutationFn: ({ id, updates }: { id: string; updates: UpdateVulnerabilityRequest }) =>
      vulnerabilitiesApi.updateVulnerability(id, updates),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
      queryClient.invalidateQueries({ queryKey: ['vulnerability-stats'] });
      setDetailsOpen(false);
    },
  });

  const markFalsePositiveMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      vulnerabilitiesApi.markFalsePositive(id, reason),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
      queryClient.invalidateQueries({ queryKey: ['vulnerability-stats'] });
    },
  });

  const acceptRiskMutation = useMutation({
    mutationFn: ({ id, justification, expiry }: { id: string; justification: string; expiry?: string }) =>
      vulnerabilitiesApi.acceptRisk(id, justification, expiry),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
      queryClient.invalidateQueries({ queryKey: ['vulnerability-stats'] });
    },
  });

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      case 'info': return 'default';
      default: return 'default';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'error';
      case 'in_progress': return 'warning';
      case 'resolved': return 'success';
      case 'false_positive': return 'default';
      case 'accepted_risk': return 'info';
      default: return 'default';
    }
  };

  const handleViewDetails = (vuln: Vulnerability) => {
    setSelectedVuln(vuln);
    setDetailsOpen(true);
  };

  const columns: GridColDef[] = [
    {
      field: 'title',
      headerName: 'Vulnerability',
      flex: 1,
      minWidth: 250,
      renderCell: (params) => (
        <Box>
          <Typography variant="body2" fontWeight="medium" sx={{ cursor: 'pointer' }} 
                     onClick={() => handleViewDetails(params.row)}>
            {params.value}
          </Typography>
          <Typography variant="caption" color="textSecondary">
            {params.row.asset}
          </Typography>
        </Box>
      ),
    },
    {
      field: 'severity',
      headerName: 'Severity',
      width: 100,
      renderCell: (params) => (
        <Chip
          label={params.value.toUpperCase()}
          size="small"
          color={getSeverityColor(params.value) as any}
          variant="filled"
        />
      ),
    },
    {
      field: 'cvss_score',
      headerName: 'CVSS',
      width: 80,
      align: 'center',
      headerAlign: 'center',
      renderCell: (params) => (
        <Typography variant="body2" fontWeight="bold">
          {params.value.toFixed(1)}
        </Typography>
      ),
    },
    {
      field: 'status',
      headerName: 'Status',
      width: 120,
      renderCell: (params) => (
        <Chip
          label={params.value.replace('_', ' ')}
          size="small"
          color={getStatusColor(params.value) as any}
          variant="outlined"
          sx={{ textTransform: 'capitalize' }}
        />
      ),
    },
    {
      field: 'cve_id',
      headerName: 'CVE',
      width: 120,
      renderCell: (params) => (
        params.value ? (
          <Link
            href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${params.value}`}
            target="_blank"
            rel="noopener noreferrer"
            sx={{ textDecoration: 'none' }}
          >
            {params.value}
            <OpenInNewIcon sx={{ ml: 0.5, fontSize: 12 }} />
          </Link>
        ) : (
          <Typography variant="body2" color="textSecondary">-</Typography>
        )
      ),
    },
    {
      field: 'port',
      headerName: 'Port',
      width: 80,
      align: 'center',
      headerAlign: 'center',
      renderCell: (params) => (
        <Typography variant="body2">
          {params.value || '-'}
        </Typography>
      ),
    },
    {
      field: 'first_detected',
      headerName: 'First Detected',
      width: 130,
      renderCell: (params) => (
        <Typography variant="body2">
          {new Date(params.value).toLocaleDateString()}
        </Typography>
      ),
    },
    {
      field: 'risk_score',
      headerName: 'Risk Score',
      width: 100,
      align: 'center',
      headerAlign: 'center',
      renderCell: (params) => (
        <Typography 
          variant="body2" 
          fontWeight="bold"
          color={params.value >= 80 ? 'error.main' : params.value >= 60 ? 'warning.main' : 'success.main'}
        >
          {params.value}
        </Typography>
      ),
    },
  ];

  return (
    <Box>
      {/* Header */}
      <Box display="flex" justifyContent="between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          Vulnerabilities
        </Typography>
        <Box display="flex" gap={1}>
          <Button
            variant="outlined"
            startIcon={<ExportIcon />}
          >
            Export
          </Button>
          <Button
            variant="outlined"
            startIcon={<FilterIcon />}
            onClick={(e) => setFilterMenuAnchor(e.currentTarget)}
          >
            Advanced Filters
          </Button>
        </Box>
      </Box>

      {/* Stats Cards */}
      <Grid container spacing={2} mb={3}>
        <Grid item xs={12} sm={6} md={2.4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <SecurityIcon color="error" sx={{ mr: 1 }} />
                <Typography color="textSecondary" variant="body2">
                  Critical
                </Typography>
              </Box>
              <Typography variant="h5" color="error.main">
                {vulnStats?.by_severity.critical || vulnerabilities.filter(v => v.severity === 'critical').length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <BugIcon color="warning" sx={{ mr: 1 }} />
                <Typography color="textSecondary" variant="body2">
                  High
                </Typography>
              </Box>
              <Typography variant="h5" color="warning.main">
                {vulnStats?.by_severity.high || vulnerabilities.filter(v => v.severity === 'high').length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <AssignmentIcon color="info" sx={{ mr: 1 }} />
                <Typography color="textSecondary" variant="body2">
                  Medium
                </Typography>
              </Box>
              <Typography variant="h5" color="info.main">
                {vulnStats?.by_severity.medium || vulnerabilities.filter(v => v.severity === 'medium').length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom variant="body2">
                Open
              </Typography>
              <Typography variant="h5" color="error.main">
                {vulnStats?.by_status.open || vulnerabilities.filter(v => v.status === 'open').length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom variant="body2">
                Resolved
              </Typography>
              <Typography variant="h5" color="success.main">
                {vulnStats?.by_status.resolved || vulnerabilities.filter(v => v.status === 'resolved').length}
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
                placeholder="Search vulnerabilities..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                InputProps={{
                  startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
                }}
              />
            </Grid>
            <Grid item xs={12} md={2}>
              <FormControl fullWidth>
                <InputLabel>Severity</InputLabel>
                <Select
                  value={severityFilter}
                  label="Severity"
                  onChange={(e) => setSeverityFilter(e.target.value)}
                >
                  <MenuItem value="all">All Severities</MenuItem>
                  <MenuItem value="critical">Critical</MenuItem>
                  <MenuItem value="high">High</MenuItem>
                  <MenuItem value="medium">Medium</MenuItem>
                  <MenuItem value="low">Low</MenuItem>
                  <MenuItem value="info">Info</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={2}>
              <FormControl fullWidth>
                <InputLabel>Status</InputLabel>
                <Select
                  value={statusFilter}
                  label="Status"
                  onChange={(e) => setStatusFilter(e.target.value)}
                >
                  <MenuItem value="all">All Statuses</MenuItem>
                  <MenuItem value="open">Open</MenuItem>
                  <MenuItem value="in_progress">In Progress</MenuItem>
                  <MenuItem value="resolved">Resolved</MenuItem>
                  <MenuItem value="false_positive">False Positive</MenuItem>
                  <MenuItem value="accepted_risk">Accepted Risk</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={4}>
              <TextField
                fullWidth
                label="Asset Filter"
                placeholder="Filter by asset name or IP"
                value={assetFilter}
                onChange={(e) => setAssetFilter(e.target.value)}
              />
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Vulnerabilities Table */}
      <Card>
        <DataGrid
          rows={vulnerabilities}
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

      {/* Vulnerability Details Dialog */}
      {selectedVuln && (
        <Dialog
          open={detailsOpen}
          onClose={() => setDetailsOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>
            {selectedVuln.title}
          </DialogTitle>
          <DialogContent>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>
                  Basic Information
                </Typography>
                <Box mb={2}>
                  <Typography variant="body2" color="textSecondary">Severity</Typography>
                  <Chip
                    label={selectedVuln.severity.toUpperCase()}
                    color={getSeverityColor(selectedVuln.severity) as any}
                    size="small"
                  />
                </Box>
                <Box mb={2}>
                  <Typography variant="body2" color="textSecondary">CVSS Score</Typography>
                  <Typography variant="body2">{selectedVuln.cvss_score.toFixed(1)}</Typography>
                </Box>
                <Box mb={2}>
                  <Typography variant="body2" color="textSecondary">Asset</Typography>
                  <Typography variant="body2">{selectedVuln.asset}</Typography>
                </Box>
                {selectedVuln.port && (
                  <Box mb={2}>
                    <Typography variant="body2" color="textSecondary">Port/Service</Typography>
                    <Typography variant="body2">{selectedVuln.port} ({selectedVuln.service})</Typography>
                  </Box>
                )}
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>
                  Identifiers
                </Typography>
                {selectedVuln.cve_id && (
                  <Box mb={2}>
                    <Typography variant="body2" color="textSecondary">CVE ID</Typography>
                    <Link
                      href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${selectedVuln.cve_id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      {selectedVuln.cve_id}
                    </Link>
                  </Box>
                )}
                {selectedVuln.cwe_id && (
                  <Box mb={2}>
                    <Typography variant="body2" color="textSecondary">CWE ID</Typography>
                    <Link
                      href={`https://cwe.mitre.org/data/definitions/${selectedVuln.cwe_id.replace('CWE-', '')}.html`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      {selectedVuln.cwe_id}
                    </Link>
                  </Box>
                )}
                <Box mb={2}>
                  <Typography variant="body2" color="textSecondary">Risk Score</Typography>
                  <Typography variant="body2" fontWeight="bold">
                    {selectedVuln.risk_score}/100
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="subtitle2" gutterBottom>
                  Description
                </Typography>
                <Typography variant="body2" paragraph>
                  {selectedVuln.description}
                </Typography>
              </Grid>
              {selectedVuln.remediation && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>
                    Remediation
                  </Typography>
                  <Typography variant="body2" paragraph>
                    {selectedVuln.remediation}
                  </Typography>
                </Grid>
              )}
              {selectedVuln.references.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>
                    References
                  </Typography>
                  {selectedVuln.references.map((ref, index) => (
                    <Box key={index} mb={1}>
                      <Link href={ref} target="_blank" rel="noopener noreferrer">
                        {ref}
                      </Link>
                    </Box>
                  ))}
                </Grid>
              )}
              <Grid item xs={12}>
                <Typography variant="subtitle2" gutterBottom>
                  Tags
                </Typography>
                <Box display="flex" flexWrap="wrap" gap={1}>
                  {selectedVuln.tags.map((tag) => (
                    <Chip key={tag} label={tag} size="small" variant="outlined" />
                  ))}
                </Box>
              </Grid>
            </Grid>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDetailsOpen(false)}>
              Close
            </Button>
            <Button variant="contained">
              Update Status
            </Button>
          </DialogActions>
        </Dialog>
      )}
    </Box>
  );
};