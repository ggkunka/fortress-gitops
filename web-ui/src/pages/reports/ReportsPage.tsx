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
  Accordion,
  AccordionSummary,
  AccordionDetails,
  FormControlLabel,
  Checkbox,
  RadioGroup,
  Radio,
  Divider,
} from '@mui/material';
import {
  Add as AddIcon,
  Download as DownloadIcon,
  Visibility as ViewIcon,
  Schedule as ScheduleIcon,
  ExpandMore as ExpandMoreIcon,
  Description as ReportIcon,
  PictureAsPdf as PdfIcon,
  TableChart as CsvIcon,
  Code as JsonIcon,
} from '@mui/icons-material';
import { DataGrid, GridColDef, GridActionsCellItem } from '@mui/x-data-grid';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { reportsApi, Report, CreateReportRequest } from '../../services/reportsApi';

export const ReportsPage: React.FC = () => {
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedReportType, setSelectedReportType] = useState('security');
  const [selectedFormat, setSelectedFormat] = useState('pdf');
  const [reportFilters, setReportFilters] = useState({
    dateRange: '30_days',
    severities: [] as string[],
    assets: [] as string[],
    scanTypes: [] as string[],
  });

  const queryClient = useQueryClient();

  // Fetch reports with API calls
  const { data: reportResponse, isLoading } = useQuery({
    queryKey: ['reports'],
    queryFn: () => reportsApi.getReports({
      page: 1,
      limit: 100,
    }),
    refetchInterval: 30000,
  });

  const reports = reportResponse?.reports || [];

  // Fetch report statistics
  const { data: reportStats } = useQuery({
    queryKey: ['report-stats'],
    queryFn: () => reportsApi.getReportStats(),
    refetchInterval: 60000,
  });

  // Mutations for report actions
  const createReportMutation = useMutation({
    mutationFn: (reportData: CreateReportRequest) => reportsApi.createReport(reportData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      queryClient.invalidateQueries({ queryKey: ['report-stats'] });
      setCreateDialogOpen(false);
    },
  });

  const generateReportMutation = useMutation({
    mutationFn: (reportId: string) => reportsApi.generateReport(reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
    },
  });

  const deleteReportMutation = useMutation({
    mutationFn: (reportId: string) => reportsApi.deleteReport(reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      queryClient.invalidateQueries({ queryKey: ['report-stats'] });
    },
  });

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'success';
      case 'generating': return 'primary';
      case 'failed': return 'error';
      case 'scheduled': return 'warning';
      default: return 'default';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'security': return <ReportIcon />;
      case 'compliance': return <ScheduleIcon />;
      case 'executive': return <ViewIcon />;
      case 'technical': return <CodeIcon />;
      case 'vulnerability': return <BugReportIcon />;
      default: return <ReportIcon />;
    }
  };

  const getFormatIcon = (format: string) => {
    switch (format) {
      case 'pdf': return <PdfIcon />;
      case 'csv': return <CsvIcon />;
      case 'json': return <JsonIcon />;
      default: return <ReportIcon />;
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return Math.round(bytes / 1024) + ' KB';
    return Math.round(bytes / 1048576 * 10) / 10 + ' MB';
  };

  const handleCreateReport = () => {
    // Implementation would create the report
    console.log('Creating report with:', {
      type: selectedReportType,
      format: selectedFormat,
      filters: reportFilters,
    });
    setCreateDialogOpen(false);
  };

  const columns: GridColDef[] = [
    {
      field: 'name',
      headerName: 'Report Name',
      flex: 1,
      minWidth: 200,
      renderCell: (params) => (
        <Box display="flex" alignItems="center">
          {getTypeIcon(params.row.type)}
          <Box ml={1}>
            <Typography variant="body2" fontWeight="medium">
              {params.value}
            </Typography>
            <Typography variant="caption" color="textSecondary">
              {params.row.type} • {params.row.format.toUpperCase()}
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
      field: 'size',
      headerName: 'Size',
      width: 100,
      renderCell: (params) => (
        <Typography variant="body2">
          {params.value ? formatFileSize(params.value) : '-'}
        </Typography>
      ),
    },
    {
      field: 'schedule',
      headerName: 'Schedule',
      width: 120,
      renderCell: (params) => (
        <Typography variant="body2">
          {params.value ? `${params.value.frequency}` : 'One-time'}
        </Typography>
      ),
    },
    {
      field: 'created_by',
      headerName: 'Created By',
      width: 120,
    },
    {
      field: 'actions',
      type: 'actions',
      headerName: 'Actions',
      width: 120,
      getActions: (params) => {
        const actions = [
          <GridActionsCellItem
            icon={<ViewIcon />}
            label="View"
            onClick={() => console.log('View report', params.row.id)}
          />,
        ];
        
        if (params.row.status === 'completed' && params.row.download_url) {
          actions.push(
            <GridActionsCellItem
              icon={<DownloadIcon />}
              label="Download"
              onClick={() => console.log('Download report', params.row.id)}
            />
          );
        }
        
        return actions;
      },
    },
  ];

  return (
    <Box>
      {/* Header */}
      <Box display="flex" justifyContent="between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          Security Reports
        </Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setCreateDialogOpen(true)}
        >
          Generate Report
        </Button>
      </Box>

      {/* Quick Stats */}
      <Grid container spacing={2} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Total Reports
              </Typography>
              <Typography variant="h5">
                {reportStats?.total_reports || reports.length}
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
                {reportStats?.completed_reports || reports.filter(r => r.status === 'completed').length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Generating
              </Typography>
              <Typography variant="h5" color="primary.main">
                {reportStats?.failed_reports || reports.filter(r => r.status === 'generating').length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Typography color="textSecondary" gutterBottom>
                Scheduled
              </Typography>
              <Typography variant="h5" color="warning.main">
                {reportStats?.scheduled_reports || reports.filter(r => r.schedule).length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Reports Table */}
      <Card>
        <DataGrid
          rows={reports}
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
          pageSizeOptions={[10, 25, 50]}
        />
      </Card>

      {/* Create Report Dialog */}
      <Dialog
        open={createDialogOpen}
        onClose={() => setCreateDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Generate New Report</DialogTitle>
        <DialogContent>
          <Alert severity="info" sx={{ mb: 3 }}>
            Configure your report parameters below. Large reports may take several minutes to generate.
          </Alert>

          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Report Type & Format</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <FormControl component="fieldset">
                    <Typography variant="subtitle2" gutterBottom>
                      Report Type
                    </Typography>
                    <RadioGroup
                      value={selectedReportType}
                      onChange={(e) => setSelectedReportType(e.target.value)}
                      row
                    >
                      <FormControlLabel value="security" control={<Radio />} label="Security Assessment" />
                      <FormControlLabel value="compliance" control={<Radio />} label="Compliance" />
                      <FormControlLabel value="executive" control={<Radio />} label="Executive Summary" />
                      <FormControlLabel value="vulnerability" control={<Radio />} label="Vulnerability Export" />
                    </RadioGroup>
                  </FormControl>
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="Report Name"
                    placeholder="e.g., Monthly Security Assessment"
                    required
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <FormControl fullWidth required>
                    <InputLabel>Output Format</InputLabel>
                    <Select
                      value={selectedFormat}
                      label="Output Format"
                      onChange={(e) => setSelectedFormat(e.target.value)}
                    >
                      <MenuItem value="pdf">PDF Document</MenuItem>
                      <MenuItem value="html">HTML Report</MenuItem>
                      <MenuItem value="csv">CSV Data Export</MenuItem>
                      <MenuItem value="json">JSON Data Export</MenuItem>
                      <MenuItem value="xlsx">Excel Spreadsheet</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Data Filters</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <FormControl fullWidth>
                    <InputLabel>Date Range</InputLabel>
                    <Select
                      value={reportFilters.dateRange}
                      label="Date Range"
                      onChange={(e) => setReportFilters({ ...reportFilters, dateRange: e.target.value })}
                    >
                      <MenuItem value="7_days">Last 7 days</MenuItem>
                      <MenuItem value="30_days">Last 30 days</MenuItem>
                      <MenuItem value="90_days">Last 90 days</MenuItem>
                      <MenuItem value="1_year">Last year</MenuItem>
                      <MenuItem value="all_time">All time</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    Severity Levels
                  </Typography>
                  <Box>
                    {['critical', 'high', 'medium', 'low', 'info'].map((severity) => (
                      <FormControlLabel
                        key={severity}
                        control={
                          <Checkbox
                            checked={reportFilters.severities.includes(severity)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setReportFilters({
                                  ...reportFilters,
                                  severities: [...reportFilters.severities, severity],
                                });
                              } else {
                                setReportFilters({
                                  ...reportFilters,
                                  severities: reportFilters.severities.filter(s => s !== severity),
                                });
                              }
                            }}
                          />
                        }
                        label={severity.charAt(0).toUpperCase() + severity.slice(1)}
                      />
                    ))}
                  </Box>
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Asset Filter"
                    placeholder="Filter by specific assets (optional)"
                    helperText="Leave empty to include all assets"
                  />
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>

          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="h6">Scheduling & Distribution</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <FormControlLabel
                    control={<Checkbox />}
                    label="Schedule this report to run automatically"
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <FormControl fullWidth disabled>
                    <InputLabel>Frequency</InputLabel>
                    <Select
                      value=""
                      label="Frequency"
                    >
                      <MenuItem value="daily">Daily</MenuItem>
                      <MenuItem value="weekly">Weekly</MenuItem>
                      <MenuItem value="monthly">Monthly</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="Email Recipients"
                    placeholder="email1@company.com, email2@company.com"
                    helperText="Comma-separated email addresses"
                  />
                </Grid>
              </Grid>
            </AccordionDetails>
          </Accordion>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleCreateReport}
          >
            Generate Report
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};