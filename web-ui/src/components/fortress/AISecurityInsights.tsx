import React, { useState } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Grid,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Avatar,
  Chip,
  Button,
  LinearProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Psychology as AIIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Lightbulb as InsightIcon,
  AutoFixHigh as AutomationIcon,
  Timeline as AnalyticsIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckIcon,
  ExpandMore as ExpandMoreIcon,
  SmartToy as BotIcon,
  Analytics as PredictiveIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';

const AISecurityInsights: React.FC = () => {
  const theme = useTheme();
  const [expandedInsight, setExpandedInsight] = useState<string | false>(false);

  const aiData = {
    summary: {
      totalInsights: 47,
      criticalInsights: 8,
      automatedActions: 156,
      accuracyRate: 94.7,
      falsePositiveRate: 2.1
    },
    insights: [
      {
        id: 'anomaly-detection-1',
        type: 'anomaly',
        severity: 'critical',
        title: 'Unusual Container Behavior Pattern Detected',
        description: 'AI model detected abnormal resource consumption and network patterns in production containers',
        confidence: 97.3,
        impact: 'High risk of crypto mining or data exfiltration',
        recommendation: 'Immediate investigation and potential container isolation required',
        affectedAssets: 12,
        timeDetected: '15 minutes ago',
        details: {
          algorithm: 'Deep Learning Anomaly Detection',
          dataPoints: 15847,
          baseline: '30-day historical average',
          deviation: '+340% CPU, +180% network traffic'
        }
      },
      {
        id: 'threat-prediction-1',
        type: 'prediction',
        severity: 'high',
        title: 'Predicted Attack Vector Based on Recent CVE Patterns',
        description: 'ML model predicts 78% probability of targeted attack on container runtime within 72 hours',
        confidence: 78.4,
        impact: 'Potential container escape and lateral movement',
        recommendation: 'Proactive patching and enhanced monitoring recommended',
        affectedAssets: 45,
        timeDetected: '2 hours ago',
        details: {
          algorithm: 'Predictive Threat Modeling',
          riskFactors: ['Unpatched CVE-2024-1234', 'Elevated privileges', 'Network exposure'],
          timeframe: '72 hours',
          preventiveActions: 'Patch available, network segmentation recommended'
        }
      },
      {
        id: 'behavioral-analysis-1',
        type: 'behavioral',
        severity: 'medium',
        title: 'Suspicious User Access Pattern Identified',
        description: 'Behavioral analysis detected unusual access patterns from service accounts',
        confidence: 89.2,
        impact: 'Potential privilege escalation or insider threat',
        recommendation: 'Review service account permissions and access logs',
        affectedAssets: 8,
        timeDetected: '4 hours ago',
        details: {
          algorithm: 'User Behavior Analytics (UBA)',
          anomalies: ['Off-hours access', 'Unusual resource access', 'Geographic anomaly'],
          baseline: '90-day user behavior profile',
          riskScore: 'Medium-High'
        }
      },
      {
        id: 'compliance-drift-1',
        type: 'compliance',
        severity: 'medium',
        title: 'Configuration Drift from Security Baseline',
        description: 'AI detected gradual deviation from established security configurations',
        confidence: 92.1,
        impact: 'Potential compliance violations and security gaps',
        recommendation: 'Automated remediation available for 80% of detected issues',
        affectedAssets: 23,
        timeDetected: '6 hours ago',
        details: {
          algorithm: 'Configuration Drift Detection',
          driftCategories: ['Network policies', 'RBAC settings', 'Resource limits'],
          remediationAvailable: true,
          estimatedFixTime: '15 minutes'
        }
      }
    ],
    automatedActions: [
      {
        id: 'auto-1',
        action: 'Container Quarantine',
        trigger: 'Malicious behavior detected',
        status: 'completed',
        timestamp: '10 minutes ago',
        impact: 'Prevented potential data breach'
      },
      {
        id: 'auto-2',
        action: 'Network Policy Update',
        trigger: 'Suspicious traffic pattern',
        status: 'completed',
        timestamp: '1 hour ago',
        impact: 'Blocked unauthorized network access'
      },
      {
        id: 'auto-3',
        action: 'Privilege Revocation',
        trigger: 'Anomalous privilege usage',
        status: 'in-progress',
        timestamp: '2 hours ago',
        impact: 'Limiting potential privilege escalation'
      }
    ],
    predictions: [
      {
        category: 'Threat Landscape',
        prediction: 'Container-based attacks expected to increase by 23% next quarter',
        confidence: 84,
        timeframe: '3 months',
        recommendation: 'Enhance container runtime security'
      },
      {
        category: 'Vulnerability Trends',
        prediction: 'Critical vulnerabilities in Kubernetes API likely within 30 days',
        confidence: 67,
        timeframe: '30 days',
        recommendation: 'Monitor security advisories closely'
      },
      {
        category: 'Compliance Risk',
        prediction: 'SOC 2 audit findings probability increased due to config drift',
        confidence: 72,
        timeframe: '2 weeks',
        recommendation: 'Immediate configuration remediation'
      }
    ]
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return '#ef4444';
      case 'high': return '#f97316';
      case 'medium': return '#eab308';
      case 'low': return '#06b6d4';
      default: return '#6b7280';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'anomaly': return <WarningIcon />;
      case 'prediction': return <PredictiveIcon />;
      case 'behavioral': return <BotIcon />;
      case 'compliance': return <SecurityIcon />;
      default: return <InsightIcon />;
    }
  };

  const handleAccordionChange = (panel: string) => (event: React.SyntheticEvent, isExpanded: boolean) => {
    setExpandedInsight(isExpanded ? panel : false);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <Card sx={{ 
        background: 'linear-gradient(135deg, #1e293b, #334155)', 
        border: '1px solid rgba(255,255,255,0.1)'
      }}>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 3, display: 'flex', alignItems: 'center' }}>
            <AIIcon sx={{ mr: 1, color: '#8b5cf6' }} />
            AI Security Insights
          </Typography>

          {/* AI Summary */}
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ 
                textAlign: 'center', 
                p: 2, 
                backgroundColor: 'rgba(139, 92, 246, 0.1)', 
                borderRadius: 2,
                border: '1px solid rgba(139, 92, 246, 0.3)'
              }}>
                <Avatar sx={{ 
                  width: 48, 
                  height: 48, 
                  mx: 'auto', 
                  mb: 1, 
                  backgroundColor: '#8b5cf6' 
                }}>
                  <InsightIcon />
                </Avatar>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#8b5cf6' }}>
                  {aiData.summary.totalInsights}
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                  AI Insights
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ 
                textAlign: 'center', 
                p: 2, 
                backgroundColor: 'rgba(16, 185, 129, 0.1)', 
                borderRadius: 2,
                border: '1px solid rgba(16, 185, 129, 0.3)'
              }}>
                <Avatar sx={{ 
                  width: 48, 
                  height: 48, 
                  mx: 'auto', 
                  mb: 1, 
                  backgroundColor: '#10b981' 
                }}>
                  <AutomationIcon />
                </Avatar>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#10b981' }}>
                  {aiData.summary.automatedActions}
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                  Auto Actions
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ 
                textAlign: 'center', 
                p: 2, 
                backgroundColor: 'rgba(59, 130, 246, 0.1)', 
                borderRadius: 2,
                border: '1px solid rgba(59, 130, 246, 0.3)'
              }}>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#3b82f6', mb: 1 }}>
                  {aiData.summary.accuracyRate}%
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                  Accuracy Rate
                </Typography>
                <LinearProgress 
                  variant="determinate" 
                  value={aiData.summary.accuracyRate}
                  sx={{ 
                    mt: 1,
                    height: 4, 
                    borderRadius: 2,
                    backgroundColor: 'rgba(255,255,255,0.1)',
                    '& .MuiLinearProgress-bar': {
                      backgroundColor: '#3b82f6'
                    }
                  }}
                />
              </Box>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Box sx={{ 
                textAlign: 'center', 
                p: 2, 
                backgroundColor: 'rgba(239, 68, 68, 0.1)', 
                borderRadius: 2,
                border: '1px solid rgba(239, 68, 68, 0.3)'
              }}>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#ef4444', mb: 1 }}>
                  {aiData.summary.falsePositiveRate}%
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                  False Positive Rate
                </Typography>
                <LinearProgress 
                  variant="determinate" 
                  value={aiData.summary.falsePositiveRate}
                  sx={{ 
                    mt: 1,
                    height: 4, 
                    borderRadius: 2,
                    backgroundColor: 'rgba(255,255,255,0.1)',
                    '& .MuiLinearProgress-bar': {
                      backgroundColor: '#10b981'
                    }
                  }}
                />
              </Box>
            </Grid>
          </Grid>

          {/* AI Insights */}
          <Typography variant="subtitle2" sx={{ mb: 2, color: 'rgba(255,255,255,0.8)' }}>
            Recent AI Insights
          </Typography>
          <Box sx={{ mb: 3 }}>
            {aiData.insights.map((insight, index) => (
              <motion.div
                key={insight.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: index * 0.1 }}
              >
                <Accordion 
                  expanded={expandedInsight === insight.id}
                  onChange={handleAccordionChange(insight.id)}
                  sx={{ 
                    backgroundColor: 'rgba(0,0,0,0.2)',
                    border: `1px solid ${alpha(getSeverityColor(insight.severity), 0.3)}`,
                    mb: 1,
                    '&:before': { display: 'none' }
                  }}
                >
                  <AccordionSummary
                    expandIcon={<ExpandMoreIcon sx={{ color: 'white' }} />}
                    sx={{ color: 'white' }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                      <Avatar sx={{ 
                        width: 32, 
                        height: 32, 
                        mr: 2,
                        backgroundColor: getSeverityColor(insight.severity)
                      }}>
                        {getTypeIcon(insight.type)}
                      </Avatar>
                      <Box sx={{ flexGrow: 1 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                          {insight.title}
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 1, mt: 0.5, alignItems: 'center' }}>
                          <Chip 
                            label={insight.severity.toUpperCase()}
                            size="small"
                            sx={{ 
                              backgroundColor: alpha(getSeverityColor(insight.severity), 0.2),
                              color: getSeverityColor(insight.severity),
                              fontSize: '0.7rem'
                            }}
                          />
                          <Chip 
                            label={`${insight.confidence}% confidence`}
                            size="small"
                            sx={{ 
                              backgroundColor: alpha('#3b82f6', 0.2),
                              color: '#3b82f6',
                              fontSize: '0.7rem'
                            }}
                          />
                          <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.6)' }}>
                            {insight.timeDetected}
                          </Typography>
                        </Box>
                      </Box>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails sx={{ color: 'white' }}>
                    <Grid container spacing={2}>
                      <Grid item xs={12} md={8}>
                        <Typography variant="body2" sx={{ mb: 2, color: 'rgba(255,255,255,0.8)' }}>
                          {insight.description}
                        </Typography>
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" sx={{ color: '#ef4444', mb: 1 }}>
                            Impact:
                          </Typography>
                          <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                            {insight.impact}
                          </Typography>
                        </Box>
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" sx={{ color: '#10b981', mb: 1 }}>
                            Recommendation:
                          </Typography>
                          <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                            {insight.recommendation}
                          </Typography>
                        </Box>
                      </Grid>
                      <Grid item xs={12} md={4}>
                        <Box sx={{ 
                          p: 2, 
                          backgroundColor: 'rgba(0,0,0,0.3)', 
                          borderRadius: 2,
                          border: '1px solid rgba(255,255,255,0.1)'
                        }}>
                          <Typography variant="subtitle2" sx={{ mb: 2, color: 'rgba(255,255,255,0.8)' }}>
                            Technical Details:
                          </Typography>
                          {Object.entries(insight.details).map(([key, value]) => (
                            <Box key={key} sx={{ mb: 1 }}>
                              <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.6)' }}>
                                {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}:
                              </Typography>
                              <Typography variant="caption" sx={{ 
                                color: 'rgba(255,255,255,0.8)', 
                                display: 'block',
                                fontFamily: 'monospace'
                              }}>
                                {Array.isArray(value) ? value.join(', ') : String(value)}
                              </Typography>
                            </Box>
                          ))}
                        </Box>
                      </Grid>
                    </Grid>
                  </AccordionDetails>
                </Accordion>
              </motion.div>
            ))}
          </Box>

          {/* Automated Actions */}
          <Typography variant="subtitle2" sx={{ mb: 2, color: 'rgba(255,255,255,0.8)' }}>
            Recent Automated Actions
          </Typography>
          <List sx={{ mb: 3 }}>
            {aiData.automatedActions.map((action, index) => (
              <motion.div
                key={action.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3, delay: index * 0.1 }}
              >
                <ListItem sx={{ 
                  backgroundColor: 'rgba(0,0,0,0.2)', 
                  borderRadius: 2, 
                  mb: 1,
                  border: '1px solid rgba(255,255,255,0.1)'
                }}>
                  <ListItemIcon>
                    <Avatar sx={{ 
                      width: 32, 
                      height: 32, 
                      backgroundColor: action.status === 'completed' ? '#10b981' : '#eab308'
                    }}>
                      <AutomationIcon />
                    </Avatar>
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                          {action.action}
                        </Typography>
                        <Chip 
                          label={action.status}
                          size="small"
                          sx={{ 
                            backgroundColor: alpha(action.status === 'completed' ? '#10b981' : '#eab308', 0.2),
                            color: action.status === 'completed' ? '#10b981' : '#eab308',
                            textTransform: 'capitalize'
                          }}
                        />
                      </Box>
                    }
                    secondary={
                      <Box sx={{ mt: 1 }}>
                        <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                          Trigger: {action.trigger}
                        </Typography>
                        <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                          Impact: {action.impact}
                        </Typography>
                        <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.5)' }}>
                          {action.timestamp}
                        </Typography>
                      </Box>
                    }
                  />
                </ListItem>
              </motion.div>
            ))}
          </List>

          {/* AI Predictions */}
          <Typography variant="subtitle2" sx={{ mb: 2, color: 'rgba(255,255,255,0.8)' }}>
            AI Predictions & Forecasts
          </Typography>
          <Grid container spacing={2}>
            {aiData.predictions.map((prediction, index) => (
              <Grid item xs={12} md={4} key={index}>
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ duration: 0.3, delay: index * 0.1 }}
                >
                  <Box sx={{ 
                    p: 2, 
                    backgroundColor: 'rgba(0,0,0,0.2)', 
                    borderRadius: 2,
                    border: '1px solid rgba(255,255,255,0.1)',
                    height: '100%'
                  }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1, color: '#8b5cf6' }}>
                      {prediction.category}
                    </Typography>
                    <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.8)', mb: 2 }}>
                      {prediction.prediction}
                    </Typography>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                      <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.6)' }}>
                        Confidence: {prediction.confidence}%
                      </Typography>
                      <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.6)' }}>
                        {prediction.timeframe}
                      </Typography>
                    </Box>
                    <LinearProgress 
                      variant="determinate" 
                      value={prediction.confidence}
                      sx={{ 
                        height: 4, 
                        borderRadius: 2,
                        backgroundColor: 'rgba(255,255,255,0.1)',
                        '& .MuiLinearProgress-bar': {
                          backgroundColor: prediction.confidence > 80 ? '#10b981' : prediction.confidence > 60 ? '#eab308' : '#ef4444'
                        }
                      }}
                    />
                    <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)', mt: 1, display: 'block' }}>
                      Recommendation: {prediction.recommendation}
                    </Typography>
                  </Box>
                </motion.div>
              </Grid>
            ))}
          </Grid>
        </CardContent>
      </Card>
    </motion.div>
  );
};

export default AISecurityInsights;
