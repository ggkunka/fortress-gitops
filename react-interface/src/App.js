import React, { useState, useEffect } from 'react';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline, AppBar, Toolbar, Typography, Drawer, List, ListItem, ListItemIcon, ListItemText, Box, Grid, Card, CardContent, Chip } from '@mui/material';
import { Dashboard, Security, Computer, BugReport, Assessment } from '@mui/icons-material';
import axios from 'axios';

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: { main: '#60a5fa' },
    background: { default: '#0f172a', paper: '#1e293b' },
  },
});

function App() {
  const [data, setData] = useState({
    securityScore: 87.3,
    totalAssets: 1247,
    criticalAlerts: 23,
    activeAgents: 45
  });

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get('/api/dashboard/overview');
        setData(response.data);
      } catch (error) {
        console.log('Using mock data');
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <AppBar position="fixed" sx={{ zIndex: 1201, background: 'linear-gradient(135deg, #1e293b, #334155)' }}>
        <Toolbar>
          <Typography variant="h6" sx={{ color: '#60a5fa', fontWeight: 700 }}>
            🏰 Fortress Security Platform
          </Typography>
        </Toolbar>
      </AppBar>
      
      <Drawer variant="permanent" sx={{ width: 280, '& .MuiDrawer-paper': { width: 280, mt: 8, background: '#1e293b' } }}>
        <List>
          <ListItem>
            <ListItemIcon><Dashboard sx={{ color: '#60a5fa' }} /></ListItemIcon>
            <ListItemText primary="Dashboard" />
          </ListItem>
          <ListItem>
            <ListItemIcon><Computer /></ListItemIcon>
            <ListItemText primary="Assets" />
            <Chip label={data.totalAssets} size="small" />
          </ListItem>
          <ListItem>
            <ListItemIcon><BugReport /></ListItemIcon>
            <ListItemText primary="Vulnerabilities" />
            <Chip label={data.criticalAlerts} color="error" size="small" />
          </ListItem>
          <ListItem>
            <ListItemIcon><Security /></ListItemIcon>
            <ListItemText primary="Agents" />
            <Chip label={data.activeAgents} color="success" size="small" />
          </ListItem>
        </List>
      </Drawer>

      <Box component="main" sx={{ ml: '280px', mt: 10, p: 3 }}>
        <Typography variant="h4" sx={{ mb: 3, color: '#f8fafc' }}>Security Dashboard</Typography>
        
        <Grid container spacing={3}>
          <Grid item xs={12} md={3}>
            <Card sx={{ background: 'linear-gradient(135deg, #1e293b, #334155)', border: '1px solid #475569' }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <Security sx={{ color: '#10b981', mr: 1 }} />
                  <Typography variant="h6">Security Score</Typography>
                </Box>
                <Typography variant="h3" sx={{ color: '#10b981' }}>{data.securityScore}%</Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={3}>
            <Card sx={{ background: 'linear-gradient(135deg, #1e293b, #334155)', border: '1px solid #475569' }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <Computer sx={{ color: '#60a5fa', mr: 1 }} />
                  <Typography variant="h6">Total Assets</Typography>
                </Box>
                <Typography variant="h3" sx={{ color: '#60a5fa' }}>{data.totalAssets}</Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={3}>
            <Card sx={{ background: 'linear-gradient(135deg, #1e293b, #334155)', border: '1px solid #475569' }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <BugReport sx={{ color: '#ef4444', mr: 1 }} />
                  <Typography variant="h6">Critical Alerts</Typography>
                </Box>
                <Typography variant="h3" sx={{ color: '#ef4444' }}>{data.criticalAlerts}</Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={3}>
            <Card sx={{ background: 'linear-gradient(135deg, #1e293b, #334155)', border: '1px solid #475569' }}>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <Assessment sx={{ color: '#10b981', mr: 1 }} />
                  <Typography variant="h6">Active Agents</Typography>
                </Box>
                <Typography variant="h3" sx={{ color: '#10b981' }}>{data.activeAgents}</Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>
    </ThemeProvider>
  );
}

export default App;
