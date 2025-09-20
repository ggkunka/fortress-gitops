import React, { useState } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Grid,
  Chip,
  LinearProgress,
  Button,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Avatar,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Lock as ComplianceIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  ExpandMore as ExpandMoreIcon,
  Assessment as ReportIcon,
  Security as SecurityIcon,
  Policy as PolicyIcon,
  Gavel as AuditIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';

interface ComplianceFrameworksProps {
  expanded?: boolean;
}

const ComplianceFrameworks: React.FC<ComplianceFrameworksProps> = ({ expanded = false }) => {
  const theme = useTheme();
  const [expandedFramework, setExpandedFramework] = useState<string | false>(false);

  const complianceData = {
    overallScore: 89,
    frameworks: [
      {
        id: 'soc2',
        name: 'SOC 2 Type II',
        score: 94,
        status: 'compliant',
        lastAudit: '2024-01-15',
        nextAudit: '2024-07-15',
        controls: {
          total: 64,
          passed: 60,
          failed: 2,
          warnings: 2
        },
        categories: [
          { name: 'Security', score: 96, status: 'compliant' },
          { name: 'Availability', score: 94, status: 'compliant' },
          { name: 'Processing Integrity', score: 92, status: 'compliant' },
          { name: 'Confidentiality', score: 95, status: 'compliant' },
          { name: 'Privacy', score: 91, status: 'compliant' }
        ],
        recentIssues: [
          'Access review documentation needs update',
          'Backup testing schedule requires adjustment'
        ]
      },
      {
        id: 'pci',
        name: 'PCI DSS',
        score: 89,
        status: 'compliant',
        lastAudit: '2024-01-10',
        nextAudit: '2024-04-10',
        controls: {
          total: 78,
          passed: 69,
          failed: 4,
          warnings: 5
        },
        categories: [
          { name: 'Network Security', score: 92, status: 'compliant' },
          { name: 'Access Control', score: 87, status: 'compliant' },
          { name: 'Data Protection', score: 91, status: 'compliant' },
          { name: 'Monitoring', score: 85, status: 'compliant' }
        ],
        recentIssues: [
          'Quarterly vulnerability scans pending',
          'Network segmentation documentation update required'
        ]
      },
      {
        id: 'gdpr',
        name: 'GDPR',
        score: 92,
        status: 'compliant',
        lastAudit: '2024-01-08',
        nextAudit: '2024-07-08',
        controls: {
          total: 45,
          passed: 41,
          failed: 1,
          warnings: 3
        },
        categories: [
          { name: 'Data Processing', score: 94, status: 'compliant' },
          { name: 'Consent Management', score: 90, status: 'compliant' },
          { name: 'Data Subject Rights', score: 93, status: 'compliant' },
          { name: 'Data Protection Impact', score: 91, status: 'compliant' }
        ],
        recentIssues: [
          'Privacy policy update required',
          'Data retention schedule review needed'
        ]
      },
      {
        id: 'hipaa',
        name: 'HIPAA',
        score: 87,
        status: 'non-compliant',
        lastAudit: '2024-01-05',
        nextAudit: '2024-04-05',
        controls: {
          total: 52,
          passed: 45,
          failed: 4,
          warnings: 3
        },
        categories: [
          { name: 'Administrative Safeguards', score: 89, status: 'compliant' },
          { name: 'Physical Safeguards', score: 85, status: 'non-compliant' },
          { name: 'Technical Safeguards', score: 87, status: 'compliant' }
        ],
        recentIssues: [
          'Physical access controls need strengthening',
          'Audit log retention policy update required',
          'Employee training completion tracking needed'
        ]
      },
      {
        id: 'iso27001',
        name: 'ISO 27001',
        score: 91,
        status: 'compliant',
        lastAudit: '2024-01-01',
        nextAudit: '2024-12-01',
        controls: {
          total: 114,
          passed: 104,
          failed: 3,
          warnings: 7
        },
        categories: [
          { name: 'Information Security Policies', score: 93, status: 'compliant' },
          { name: 'Risk Management', score: 90, status: 'compliant' },
          { name: 'Asset Management', score: 89, status: 'compliant' },
          { name: 'Access Control', score: 92, status: 'compliant' },
          { name: 'Incident Management', score: 91, status: 'compliant' }
        ],
        recentIssues: [
          'Risk assessment documentation update needed',
          'Asset inventory requires quarterly review'
        ]
      }
    ]
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'compliant': return '#10b981';
      case 'non-compliant': return '#ef4444';
      case 'warning': return '#eab308';
      default: return '#6b7280';
    }
  };

  const handleAccordionChange = (panel: string) => (event: React.SyntheticEvent, isExpanded: boolean) => {
    setExpandedFramework(isExpanded ? panel : false);
  };

  const displayedFrameworks = expanded ? complianceData.frameworks : complianceData.frameworks.slice(0, 3);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.6 }}
    >
      <Card sx={{ 
        background: 'linear-gradient(135deg, #1e293b, #334155)', 
        border: '1px solid rgba(255,255,255,0.1)'
      }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
              <ComplianceIcon sx={{ mr: 1, color: '#8b5cf6' }} />
              Compliance Frameworks
            </Typography>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Chip 
                label={`Overall Score: ${complianceData.overallScore}%`}
                sx={{ 
                  backgroundColor: alpha('#10b981', 0.2),
                  color: '#10b981',
                  fontWeight: 600
                }}
              />
              <Button 
                size="small" 
                startIcon={<ReportIcon />}
                sx={{ color: 'rgba(255,255,255,0.7)' }}
              >
                Generate Report
              </Button>
            </Box>
          </Box>

          {!expanded && (
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {complianceData.frameworks.map((framework) => (
                <Grid item xs={12} sm={6} md={2.4} key={framework.id}>
                  <motion.div
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ duration: 0.3 }}
                  >
                    <Box sx={{ 
                      textAlign: 'center', 
                      p: 2, 
                      backgroundColor: 'rgba(0,0,0,0.2)', 
                      borderRadius: 2,
                      border: `1px solid ${getStatusColor(framework.status)}`,
                      height: '100%'
                    }}>
                      <Avatar sx={{ 
                        width: 48, 
                        height: 48, 
                        mx: 'auto', 
                        mb: 1,
                        backgroundColor: getStatusColor(framework.status)
                      }}>
                        {framework.status === 'compliant' ? <CheckIcon /> : <ErrorIcon />}
                      </Avatar>
                      <Typography variant="h4" sx={{ 
                        fontWeight: 700, 
                        color: getStatusColor(framework.status),
                        mb: 1 
                      }}>
                        {framework.score}%
                      </Typography>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                        {framework.name}
                      </Typography>
                      <Chip 
                        label={framework.status === 'compliant' ? 'Compliant' : 'Non-Compliant'}
                        size="small"
                        sx={{ 
                          backgroundColor: alpha(getStatusColor(framework.status), 0.2),
                          color: getStatusColor(framework.status)
                        }}
                      />
                    </Box>
                  </motion.div>
                </Grid>
              ))}
            </Grid>
          )}

          {expanded && (
            <Box>
              {displayedFrameworks.map((framework, index) => (
                <motion.div
                  key={framework.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, delay: index * 0.1 }}
                >
                  <Accordion 
                    expanded={expandedFramework === framework.id}
                    onChange={handleAccordionChange(framework.id)}
                    sx={{ 
                      backgroundColor: 'rgba(0,0,0,0.2)',
                      border: `1px solid ${alpha(getStatusColor(framework.status), 0.3)}`,
                      mb: 2,
                      '&:before': { display: 'none' }
                    }}
                  >
                    <AccordionSummary
                      expandIcon={<ExpandMoreIcon sx={{ color: 'white' }} />}
                      sx={{ color: 'white' }}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                        <Avatar sx={{ 
                          width: 40, 
                          height: 40, 
                          mr: 2,
                          backgroundColor: getStatusColor(framework.status)
                        }}>
                          {framework.status === 'compliant' ? <CheckIcon /> : <ErrorIcon />}
                        </Avatar>
                        <Box sx={{ flexGrow: 1 }}>
                          <Typography variant="h6" sx={{ fontWeight: 600 }}>
                            {framework.name}
                          </Typography>
                          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', mt: 1 }}>
                            <Typography variant="h5" sx={{ 
                              color: getStatusColor(framework.status),
                              fontWeight: 700
                            }}>
                              {framework.score}%
                            </Typography>
                            <Chip 
                              label={framework.status === 'compliant' ? 'Compliant' : 'Non-Compliant'}
                              size="small"
                              sx={{ 
                                backgroundColor: alpha(getStatusColor(framework.status), 0.2),
                                color: getStatusColor(framework.status)
                              }}
                            />
                            <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.6)' }}>
                              Last Audit: {framework.lastAudit}
                            </Typography>
                          </Box>
                        </Box>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails sx={{ color: 'white' }}>
                      <Grid container spacing={3}>
                        <Grid item xs={12} md={6}>
                          <Typography variant="subtitle2" sx={{ mb: 2, color: 'rgba(255,255,255,0.8)' }}>
                            Control Status
                          </Typography>
                          <Box sx={{ 
                            display: 'flex', 
                            justifyContent: 'space-around',
                            p: 2,
                            backgroundColor: 'rgba(0,0,0,0.3)',
                            borderRadius: 2
                          }}>
                            <Box sx={{ textAlign: 'center' }}>
                              <Typography variant="h6" sx={{ color: '#10b981', fontWeight: 700 }}>
                                {framework.controls.passed}
                              </Typography>
                              <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                                Passed
                              </Typography>
                            </Box>
                            <Box sx={{ textAlign: 'center' }}>
                              <Typography variant="h6" sx={{ color: '#ef4444', fontWeight: 700 }}>
                                {framework.controls.failed}
                              </Typography>
                              <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                                Failed
                              </Typography>
                            </Box>
                            <Box sx={{ textAlign: 'center' }}>
                              <Typography variant="h6" sx={{ color: '#eab308', fontWeight: 700 }}>
                                {framework.controls.warnings}
                              </Typography>
                              <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                                Warnings
                              </Typography>
                            </Box>
                          </Box>
                        </Grid>
                        <Grid item xs={12} md={6}>
                          <Typography variant="subtitle2" sx={{ mb: 2, color: 'rgba(255,255,255,0.8)' }}>
                            Categories
                          </Typography>
                          {framework.categories.map((category) => (
                            <Box key={category.name} sx={{ mb: 2 }}>
                              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                                  {category.name}
                                </Typography>
                                <Typography variant="body2" sx={{ 
                                  color: getStatusColor(category.status), 
                                  fontWeight: 600 
                                }}>
                                  {category.score}%
                                </Typography>
                              </Box>
                              <LinearProgress 
                                variant="determinate" 
                                value={category.score}
                                sx={{ 
                                  height: 6, 
                                  borderRadius: 3,
                                  backgroundColor: 'rgba(255,255,255,0.1)',
                                  '& .MuiLinearProgress-bar': {
                                    backgroundColor: getStatusColor(category.status),
                                    borderRadius: 3
                                  }
                                }}
                              />
                            </Box>
                          ))}
                        </Grid>
                        {framework.recentIssues.length > 0 && (
                          <Grid item xs={12}>
                            <Typography variant="subtitle2" sx={{ mb: 2, color: 'rgba(255,255,255,0.8)' }}>
                              Recent Issues
                            </Typography>
                            <List>
                              {framework.recentIssues.map((issue, idx) => (
                                <ListItem key={idx} sx={{ py: 0.5 }}>
                                  <ListItemIcon>
                                    <WarningIcon sx={{ color: '#eab308', fontSize: 20 }} />
                                  </ListItemIcon>
                                  <ListItemText 
                                    primary={issue}
                                    sx={{ color: 'rgba(255,255,255,0.8)' }}
                                  />
                                </ListItem>
                              ))}
                            </List>
                          </Grid>
                        )}
                      </Grid>
                    </AccordionDetails>
                  </Accordion>
                </motion.div>
              ))}
            </Box>
          )}

          {!expanded && (
            <Box sx={{ textAlign: 'center', mt: 3 }}>
              <Button 
                variant="outlined" 
                sx={{ 
                  color: 'white', 
                  borderColor: 'rgba(255,255,255,0.3)',
                  '&:hover': {
                    borderColor: 'rgba(255,255,255,0.5)',
                    backgroundColor: 'rgba(255,255,255,0.05)'
                  }
                }}
              >
                View All Frameworks
              </Button>
            </Box>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
};

export default ComplianceFrameworks;
