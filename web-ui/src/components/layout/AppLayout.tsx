import React, { useState } from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import {
  AppBar,
  Box,
  CssBaseline,
  Drawer,
  IconButton,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Toolbar,
  Typography,
  Avatar,
  Menu,
  MenuItem,
  Divider,
  Badge,
  useTheme,
  useMediaQuery,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Dashboard as DashboardIcon,
  Security as SecurityIcon,
  BugReport as VulnerabilityIcon,
  Assessment as ReportsIcon,
  Extension as IntegrationsIcon,
  Store as MarketplaceIcon,
  Settings as SettingsIcon,
  Notifications as NotificationsIcon,
  AccountCircle as AccountIcon,
  Logout as LogoutIcon,
  Help as HelpIcon,
  Shield as FortressIcon,
  Cloud as CloudIcon,
  AccountTree as ClustersIcon,
  Storage as RepositoriesIcon,
} from '@mui/icons-material';

import { useAuth } from '../../contexts/AuthContext';
// import { useNotifications } from '../../hooks/useNotifications';

const drawerWidth = 240;

interface NavigationItem {
  id: string;
  label: string;
  path: string;
  icon: React.ReactElement;
  badge?: number;
}

const navigationItems: NavigationItem[] = [
  {
    id: 'fortress',
    label: 'Fortress Dashboard',
    path: '/',
    icon: <FortressIcon />,
  },
  {
    id: 'clusters',
    label: 'Clusters',
    path: '/clusters',
    icon: <ClustersIcon />,
  },
  {
    id: 'repositories',
    label: 'Repositories',
    path: '/repositories',
    icon: <RepositoriesIcon />,
  },
  {
    id: 'scans',
    label: 'Security Scans',
    path: '/scans',
    icon: <SecurityIcon />,
  },
  {
    id: 'vulnerabilities',
    label: 'Vulnerabilities',
    path: '/vulnerabilities',
    icon: <VulnerabilityIcon />,
  },
  {
    id: 'reports',
    label: 'Reports',
    path: '/reports',
    icon: <ReportsIcon />,
  },
  {
    id: 'integrations',
    label: 'Integrations',
    path: '/integrations',
    icon: <IntegrationsIcon />,
  },
  {
    id: 'marketplace',
    label: 'Plugin Marketplace',
    path: '/marketplace',
    icon: <MarketplaceIcon />,
  },
];

export const AppLayout: React.FC = () => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuth();
  // const { data: notifications } = useNotifications();
  const notifications: any[] = []; // Placeholder for notifications

  const [mobileOpen, setMobileOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = async () => {
    handleMenuClose();
    await logout();
    navigate('/login');
  };

  const handleNavigation = (path: string) => {
    navigate(path);
    if (isMobile) {
      setMobileOpen(false);
    }
  };

  const isActivePath = (path: string) => {
    return location.pathname === path || location.pathname.startsWith(path + '/');
  };

  const unreadNotifications = notifications?.filter((n) => !n.read).length || 0;

  const drawer = (
    <Box>
      <Toolbar>
        <Typography variant="h6" noWrap component="div" sx={{ fontWeight: 'bold' }}>
          🏰 Fortress
        </Typography>
      </Toolbar>
      <Divider />
      <List>
        {navigationItems.map((item) => (
          <ListItem key={item.id} disablePadding>
            <ListItemButton
              selected={isActivePath(item.path)}
              onClick={() => handleNavigation(item.path)}
              sx={{
                '&.Mui-selected': {
                  backgroundColor: theme.palette.primary.main + '20',
                  color: theme.palette.primary.main,
                  '& .MuiListItemIcon-root': {
                    color: theme.palette.primary.main,
                  },
                },
              }}
            >
              <ListItemIcon>
                {item.badge ? (
                  <Badge badgeContent={item.badge} color="error">
                    {item.icon}
                  </Badge>
                ) : (
                  item.icon
                )}
              </ListItemIcon>
              <ListItemText primary={item.label} />
            </ListItemButton>
          </ListItem>
        ))}
      </List>
    </Box>
  );

  return (
    <Box sx={{ display: 'flex' }}>
      <CssBaseline />

      {/* App Bar */}
      <AppBar
        position="fixed"
        sx={{
          width: { md: `calc(100% - ${drawerWidth}px)` },
          ml: { md: `${drawerWidth}px` },
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{ mr: 2, display: { md: 'none' } }}
          >
            <MenuIcon />
          </IconButton>

          <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1 }}>
            {navigationItems.find((item) => isActivePath(item.path))?.label ||
              'Fortress Security Platform'}
          </Typography>

          {/* Notifications */}
          <IconButton size="large" color="inherit">
            <Badge badgeContent={unreadNotifications} color="error">
              <NotificationsIcon />
            </Badge>
          </IconButton>

          {/* User Menu */}
          <IconButton
            size="large"
            edge="end"
            aria-label="account of current user"
            aria-controls="menu-appbar"
            aria-haspopup="true"
            onClick={handleMenuOpen}
            color="inherit"
          >
            <Avatar sx={{ width: 32, height: 32, bgcolor: theme.palette.secondary.main }}>
              {user?.first_name?.[0] || user?.username?.[0] || 'U'}
            </Avatar>
          </IconButton>

          <Menu
            id="menu-appbar"
            anchorEl={anchorEl}
            anchorOrigin={{
              vertical: 'top',
              horizontal: 'right',
            }}
            keepMounted
            transformOrigin={{
              vertical: 'top',
              horizontal: 'right',
            }}
            open={Boolean(anchorEl)}
            onClose={handleMenuClose}
          >
            <MenuItem onClick={handleMenuClose}>
              <ListItemIcon>
                <AccountIcon fontSize="small" />
              </ListItemIcon>
              <Typography variant="inherit">
                {user?.first_name} {user?.last_name}
              </Typography>
            </MenuItem>
            <MenuItem onClick={handleMenuClose}>
              <ListItemIcon>
                <SettingsIcon fontSize="small" />
              </ListItemIcon>
              <Typography variant="inherit">Profile Settings</Typography>
            </MenuItem>
            <MenuItem onClick={handleMenuClose}>
              <ListItemIcon>
                <HelpIcon fontSize="small" />
              </ListItemIcon>
              <Typography variant="inherit">Help & Support</Typography>
            </MenuItem>
            <Divider />
            <MenuItem onClick={handleLogout}>
              <ListItemIcon>
                <LogoutIcon fontSize="small" />
              </ListItemIcon>
              <Typography variant="inherit">Logout</Typography>
            </MenuItem>
          </Menu>
        </Toolbar>
      </AppBar>

      {/* Navigation Drawer */}
      <Box
        component="nav"
        sx={{ width: { md: drawerWidth }, flexShrink: { md: 0 } }}
        aria-label="mailbox folders"
      >
        {/* Mobile drawer */}
        <Drawer
          variant="temporary"
          open={mobileOpen}
          onClose={handleDrawerToggle}
          ModalProps={{
            keepMounted: true, // Better open performance on mobile.
          }}
          sx={{
            display: { xs: 'block', md: 'none' },
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: drawerWidth,
            },
          }}
        >
          {drawer}
        </Drawer>

        {/* Desktop drawer */}
        <Drawer
          variant="permanent"
          sx={{
            display: { xs: 'none', md: 'block' },
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: drawerWidth,
            },
          }}
          open
        >
          {drawer}
        </Drawer>
      </Box>

      {/* Main Content */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          width: { md: `calc(100% - ${drawerWidth}px)` },
          minHeight: '100vh',
          backgroundColor: theme.palette.background.default,
        }}
      >
        <Toolbar />
        <Outlet />
      </Box>
    </Box>
  );
};
