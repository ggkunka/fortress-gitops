import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  CardActions,
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
  Rating,
  Avatar,
  Badge,
  IconButton,
  Tabs,
  Tab,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material';
import {
  Search as SearchIcon,
  GetApp as DownloadIcon,
  Star as StarIcon,
  Verified as VerifiedIcon,
  Security as SecurityIcon,
  Code as CodeIcon,
  Assessment as AssessmentIcon,
  Cloud as CloudIcon,
  Extension as ExtensionIcon,
  CheckCircle as CheckIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  BugReport as BugReportIcon,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { pluginsApi, Plugin, InstalledPlugin } from '../../services/pluginsApi';

interface Review {
  id: string;
  plugin_id: string;
  user: string;
  rating: number;
  comment: string;
  created_at: string;
  helpful_count: number;
}

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
      {...other}
    >
      {value === index && <Box>{children}</Box>}
    </div>
  );
}

export const MarketplacePage: React.FC = () => {
  const [tabValue, setTabValue] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [sortBy, setSortBy] = useState('popular');
  const [selectedPlugin, setSelectedPlugin] = useState<Plugin | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);

  const queryClient = useQueryClient();

  // Fetch plugins with API calls
  const { data: pluginResponse, isLoading } = useQuery({
    queryKey: ['plugins', searchTerm, categoryFilter, sortBy, tabValue],
    queryFn: () => pluginsApi.getPlugins({
      search: searchTerm || undefined,
      category: categoryFilter !== 'all' ? categoryFilter : undefined,
      sort_by: sortBy as any,
      price: tabValue === 1 ? 'free' : tabValue === 2 ? 'paid' : 'all',
      official: tabValue === 3 ? true : undefined,
      page: 1,
      limit: 50,
    }),
    refetchInterval: 60000,
  });

  const plugins = pluginResponse?.plugins || [];

  // Fetch installed plugins
  const { data: installedPlugins = [] } = useQuery({
    queryKey: ['installed-plugins'],
    queryFn: () => pluginsApi.getInstalledPlugins(),
    refetchInterval: 30000,
  });

  // Fetch plugin statistics
  const { data: pluginStats } = useQuery({
    queryKey: ['plugin-stats'],
    queryFn: () => pluginsApi.getPluginStats(),
    refetchInterval: 60000,
  });

  // Fetch popular and featured plugins
  const { data: popularPlugins = [] } = useQuery({
    queryKey: ['popular-plugins'],
    queryFn: () => pluginsApi.getPopularPlugins(10),
  });

  const { data: featuredPlugins = [] } = useQuery({
    queryKey: ['featured-plugins'],
    queryFn: () => pluginsApi.getFeaturedPlugins(),
  });

  // Mutations for plugin actions
  const installPluginMutation = useMutation({
    mutationFn: (pluginId: string) => pluginsApi.installPlugin(pluginId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['installed-plugins'] });
      queryClient.invalidateQueries({ queryKey: ['plugin-stats'] });
    },
  });

  const uninstallPluginMutation = useMutation({
    mutationFn: (pluginId: string) => pluginsApi.uninstallPlugin(pluginId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['installed-plugins'] });
      queryClient.invalidateQueries({ queryKey: ['plugin-stats'] });
    },
  });

  const togglePluginMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      pluginsApi.togglePlugin(id, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['installed-plugins'] });
    },
  });

  // Check if plugin is installed
  const isPluginInstalled = (pluginId: string) => {
    return installedPlugins.some(installed => installed.plugin_id === pluginId);
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'scanner': return <SecurityIcon />;
      case 'integration': return <CloudIcon />;
      case 'reporting': return <AssessmentIcon />;
      case 'analysis': return <CodeIcon />;
      case 'automation': return <ExtensionIcon />;
      default: return <ExtensionIcon />;
    }
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'scanner': return '#f44336';
      case 'integration': return '#2196f3';
      case 'reporting': return '#4caf50';
      case 'analysis': return '#ff9800';
      case 'automation': return '#9c27b0';
      default: return '#666';
    }
  };

  const handleViewDetails = (plugin: Plugin) => {
    setSelectedPlugin(plugin);
    setDetailsOpen(true);
  };

  const installPlugin = useMutation({
    mutationFn: async (pluginId: string) => {
      await new Promise(resolve => setTimeout(resolve, 2000));
      return pluginId;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
    },
  });

  const filterPlugins = () => {
    let filtered = plugins;
    
    if (searchTerm) {
      filtered = filtered.filter(plugin =>
        plugin.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        plugin.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        plugin.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()))
      );
    }
    
    if (categoryFilter !== 'all') {
      filtered = filtered.filter(plugin => plugin.category === categoryFilter);
    }
    
    switch (sortBy) {
      case 'popular':
        return filtered.sort((a, b) => b.downloads - a.downloads);
      case 'rating':
        return filtered.sort((a, b) => b.rating - a.rating);
      case 'newest':
        return filtered.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
      case 'price_low':
        return filtered.sort((a, b) => a.price - b.price);
      default:
        return filtered;
    }
  };

  return (
    <Box>
      {/* Header */}
      <Box display="flex" justifyContent="between" alignItems="center" mb={3}>
        <Typography variant="h4" component="h1">
          Plugin Marketplace
        </Typography>
        <Button variant="outlined">
          Manage Installed
        </Button>
      </Box>

      {/* Search and Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} md={4}>
              <TextField
                fullWidth
                placeholder="Search plugins..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                InputProps={{
                  startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
                }}
              />
            </Grid>
            <Grid item xs={12} md={2}>
              <FormControl fullWidth>
                <InputLabel>Category</InputLabel>
                <Select
                  value={categoryFilter}
                  label="Category"
                  onChange={(e) => setCategoryFilter(e.target.value)}
                >
                  <MenuItem value="all">All Categories</MenuItem>
                  <MenuItem value="scanner">Scanners</MenuItem>
                  <MenuItem value="integration">Integrations</MenuItem>
                  <MenuItem value="reporting">Reporting</MenuItem>
                  <MenuItem value="analysis">Analysis</MenuItem>
                  <MenuItem value="automation">Automation</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={2}>
              <FormControl fullWidth>
                <InputLabel>Sort By</InputLabel>
                <Select
                  value={sortBy}
                  label="Sort By"
                  onChange={(e) => setSortBy(e.target.value)}
                >
                  <MenuItem value="popular">Most Popular</MenuItem>
                  <MenuItem value="rating">Highest Rated</MenuItem>
                  <MenuItem value="newest">Newest</MenuItem>
                  <MenuItem value="price_low">Price: Low to High</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box display="flex" gap={1}>
                <Tabs
                  value={tabValue}
                  onChange={(e, newValue) => setTabValue(newValue)}
                  variant="scrollable"
                  scrollButtons="auto"
                >
                  <Tab label="All" />
                  <Tab label="Free" />
                  <Tab label="Paid" />
                  <Tab label="Official" />
                </Tabs>
              </Box>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Plugin Grid */}
      <Grid container spacing={3}>
        {filterPlugins().map((plugin) => (
          <Grid item xs={12} sm={6} md={4} key={plugin.id}>
            <Card 
              sx={{ 
                height: '100%', 
                display: 'flex', 
                flexDirection: 'column',
                '&:hover': { transform: 'translateY(-2px)', transition: 'transform 0.2s' }
              }}
            >
              <CardContent sx={{ flexGrow: 1 }}>
                <Box display="flex" alignItems="center" mb={2}>
                  <Avatar
                    sx={{ 
                      bgcolor: getCategoryColor(plugin.category), 
                      width: 40, 
                      height: 40, 
                      mr: 2 
                    }}
                  >
                    {getCategoryIcon(plugin.category)}
                  </Avatar>
                  <Box flexGrow={1}>
                    <Box display="flex" alignItems="center" gap={1}>
                      <Typography variant="h6" component="h3" noWrap>
                        {plugin.name}
                      </Typography>
                      {plugin.official && (
                        <Badge color="primary">
                          <VerifiedIcon sx={{ fontSize: 16 }} />
                        </Badge>
                      )}
                    </Box>
                    <Typography variant="caption" color="textSecondary">
                      by {plugin.author} {plugin.author_verified && <VerifiedIcon sx={{ fontSize: 12, color: 'primary.main' }} />}
                    </Typography>
                  </Box>
                </Box>

                <Typography variant="body2" color="textSecondary" paragraph>
                  {plugin.description}
                </Typography>

                <Box display="flex" alignItems="center" gap={1} mb={2}>
                  <Rating value={plugin.rating} precision={0.1} size="small" readOnly />
                  <Typography variant="caption">
                    ({plugin.reviews_count})
                  </Typography>
                  <Chip 
                    label={plugin.category} 
                    size="small" 
                    sx={{ 
                      backgroundColor: getCategoryColor(plugin.category),
                      color: 'white',
                      textTransform: 'capitalize'
                    }} 
                  />
                </Box>

                <Box display="flex" flexWrap="wrap" gap={0.5} mb={2}>
                  {plugin.tags.slice(0, 3).map((tag) => (
                    <Chip 
                      key={tag} 
                      label={tag} 
                      size="small" 
                      variant="outlined"
                      sx={{ fontSize: '0.7rem' }}
                    />
                  ))}
                  {plugin.tags.length > 3 && (
                    <Chip 
                      label={`+${plugin.tags.length - 3}`} 
                      size="small" 
                      variant="outlined"
                      sx={{ fontSize: '0.7rem' }}
                    />
                  )}
                </Box>

                <Box display="flex" justifyContent="between" alignItems="center">
                  <Typography variant="h6" color="primary">
                    {plugin.price === 0 ? 'Free' : `$${plugin.price}`}
                  </Typography>
                  <Typography variant="caption" color="textSecondary">
                    {plugin.downloads.toLocaleString()} downloads
                  </Typography>
                </Box>
              </CardContent>

              <CardActions>
                <Box display="flex" width="100%" gap={1}>
                  {isPluginInstalled(plugin.id) ? (
                    <Button fullWidth variant="outlined" color="success" startIcon={<CheckIcon />}>
                      Installed
                    </Button>
                  ) : (
                    <Button
                      fullWidth
                      variant="contained"
                      startIcon={<DownloadIcon />}
                      onClick={() => installPluginMutation.mutate(plugin.id)}
                      disabled={installPluginMutation.isPending}
                    >
                      {installPluginMutation.isPending ? 'Installing...' : 'Install'}
                    </Button>
                  )}
                  <Button
                    variant="outlined"
                    onClick={() => handleViewDetails(plugin)}
                  >
                    Details
                  </Button>
                </Box>
              </CardActions>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Plugin Details Dialog */}
      {selectedPlugin && (
        <Dialog
          open={detailsOpen}
          onClose={() => setDetailsOpen(false)}
          maxWidth="md"
          fullWidth
        >
          <DialogTitle>
            <Box display="flex" alignItems="center" gap={2}>
              <Avatar
                sx={{ 
                  bgcolor: getCategoryColor(selectedPlugin.category), 
                  width: 48, 
                  height: 48 
                }}
              >
                {getCategoryIcon(selectedPlugin.category)}
              </Avatar>
              <Box>
                <Typography variant="h5">
                  {selectedPlugin.name}
                  {selectedPlugin.official && (
                    <VerifiedIcon sx={{ ml: 1, color: 'primary.main' }} />
                  )}
                </Typography>
                <Typography variant="subtitle2" color="textSecondary">
                  Version {selectedPlugin.version} by {selectedPlugin.author}
                </Typography>
              </Box>
            </Box>
          </DialogTitle>
          <DialogContent>
            <Box mb={3}>
              <Typography variant="body1" paragraph>
                {selectedPlugin.description}
              </Typography>
              
              <Box display="flex" alignItems="center" gap={2} mb={2}>
                <Rating value={selectedPlugin.rating} precision={0.1} readOnly />
                <Typography variant="body2">
                  {selectedPlugin.rating} ({selectedPlugin.reviews_count} reviews)
                </Typography>
                <Typography variant="h6" color="primary">
                  {selectedPlugin.price === 0 ? 'Free' : `$${selectedPlugin.price}`}
                </Typography>
              </Box>

              <Typography variant="h6" gutterBottom>
                Features & Tags
              </Typography>
              <Box display="flex" flexWrap="wrap" gap={1} mb={3}>
                {selectedPlugin.tags.map((tag) => (
                  <Chip key={tag} label={tag} size="small" variant="outlined" />
                ))}
              </Box>

              <Typography variant="h6" gutterBottom>
                Requirements
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemIcon>
                    <InfoIcon color="primary" />
                  </ListItemIcon>
                  <ListItemText 
                    primary="Minimum Platform Version" 
                    secondary={selectedPlugin.requirements.min_platform_version}
                  />
                </ListItem>
                {selectedPlugin.requirements.dependencies.length > 0 && (
                  <ListItem>
                    <ListItemIcon>
                      <WarningIcon color="warning" />
                    </ListItemIcon>
                    <ListItemText 
                      primary="Dependencies" 
                      secondary={selectedPlugin.requirements.dependencies.join(', ')}
                    />
                  </ListItem>
                )}
                <ListItem>
                  <ListItemIcon>
                    <SecurityIcon color="error" />
                  </ListItemIcon>
                  <ListItemText 
                    primary="Required Permissions" 
                    secondary={selectedPlugin.requirements.permissions.join(', ')}
                  />
                </ListItem>
              </List>

              {selectedPlugin.changelog && (
                <>
                  <Typography variant="h6" gutterBottom>
                    Recent Changes
                  </Typography>
                  <Typography variant="body2" color="textSecondary" paragraph>
                    {selectedPlugin.changelog}
                  </Typography>
                </>
              )}

              <Box display="flex" gap={1} mt={2}>
                {selectedPlugin.documentation_url && (
                  <Button size="small" href={selectedPlugin.documentation_url} target="_blank">
                    Documentation
                  </Button>
                )}
                {selectedPlugin.source_url && (
                  <Button size="small" href={selectedPlugin.source_url} target="_blank">
                    Source Code
                  </Button>
                )}
              </Box>
            </Box>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDetailsOpen(false)}>
              Close
            </Button>
            {isPluginInstalled(selectedPlugin.id) ? (
              <Button variant="outlined" color="success" startIcon={<CheckIcon />}>
                Installed
              </Button>
            ) : (
              <Button
                variant="contained"
                startIcon={<DownloadIcon />}
                onClick={() => {
                  installPluginMutation.mutate(selectedPlugin.id);
                  setDetailsOpen(false);
                }}
                disabled={installPluginMutation.isPending}
              >
                Install Plugin
              </Button>
            )}
          </DialogActions>
        </Dialog>
      )}
    </Box>
  );
};