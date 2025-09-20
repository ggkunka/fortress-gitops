import React from 'react';
import {
  Card,
  CardContent,
  Typography,
  Avatar,
  Chip,
  Box,
  LinearProgress,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Shield as ShieldIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';

const SecurityPostureCard: React.FC = () => {
  const theme = useTheme();
  
  const securityData = {
    score: 847,
    grade: 'A',
    trend: 12,
    previousScore: 835,
    categories: [
      { name: 'Identity & Access', score: 92, color: '#10b981' },
      { name: 'Network Security', score: 88, color: '#3b82f6' },
      { name: 'Data Protection', score: 94, color: '#8b5cf6' },
      { name: 'Workload Security', score: 85, color: '#f59e0b' },
    ]
  };

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case 'A': return '#10b981';
      case 'B': return '#3b82f6';
      case 'C': return '#f59e0b';
      case 'D': return '#ef4444';
      default: return '#6b7280';
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <Card sx={{ 
        background: 'linear-gradient(135deg, #1e293b, #334155)', 
        border: '1px solid rgba(255,255,255,0.1)',
        height: '100%',
        position: 'relative',
        overflow: 'hidden'
      }}>
        {/* Background Pattern */}
        <Box sx={{
          position: 'absolute',
          top: 0,
          right: 0,
          width: '50%',
          height: '100%',
          background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.1), rgba(59, 130, 246, 0.1))',
          clipPath: 'polygon(50% 0%, 100% 0%, 100% 100%, 0% 100%)'
        }} />
        
        <CardContent sx={{ textAlign: 'center', py: 3, position: 'relative', zIndex: 1 }}>
          <Avatar sx={{ 
            width: 64, 
            height: 64, 
            mx: 'auto', 
            mb: 2, 
            background: `linear-gradient(135deg, ${getGradeColor(securityData.grade)}, ${alpha(getGradeColor(securityData.grade), 0.7)})`,
            boxShadow: `0 8px 32px ${alpha(getGradeColor(securityData.grade), 0.3)}`
          }}>
            <ShieldIcon sx={{ fontSize: 32 }} />
          </Avatar>
          
          <Typography variant="h2" sx={{ 
            fontWeight: 800, 
            mb: 1,
            background: `linear-gradient(135deg, ${getGradeColor(securityData.grade)}, #ffffff)`,
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent'
          }}>
            {securityData.score}
          </Typography>
          
          <Typography variant="h5" sx={{ 
            color: getGradeColor(securityData.grade), 
            mb: 2,
            fontWeight: 600
          }}>
            Security Score (Grade {securityData.grade})
          </Typography>
          
          <Chip 
            label={`${securityData.trend > 0 ? '+' : ''}${securityData.trend} this week`}
            size="small"
            icon={securityData.trend > 0 ? <TrendingUpIcon /> : <TrendingDownIcon />}
            sx={{ 
              backgroundColor: alpha(securityData.trend > 0 ? '#10b981' : '#ef4444', 0.2),
              color: securityData.trend > 0 ? '#10b981' : '#ef4444',
              mb: 3
            }}
          />

          {/* Security Categories */}
          <Box sx={{ mt: 3 }}>
            <Typography variant="subtitle2" sx={{ mb: 2, color: 'rgba(255,255,255,0.8)' }}>
              Security Categories
            </Typography>
            {securityData.categories.map((category, index) => (
              <Box key={category.name} sx={{ mb: 2 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                    {category.name}
                  </Typography>
                  <Typography variant="body2" sx={{ color: category.color, fontWeight: 600 }}>
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
                      backgroundColor: category.color,
                      borderRadius: 3
                    }
                  }}
                />
              </Box>
            ))}
          </Box>

          {/* Improvement Indicator */}
          <Box sx={{ 
            mt: 3, 
            p: 2, 
            backgroundColor: 'rgba(16, 185, 129, 0.1)',
            borderRadius: 2,
            border: '1px solid rgba(16, 185, 129, 0.2)'
          }}>
            <Typography variant="body2" sx={{ color: '#10b981', fontWeight: 600 }}>
              🎯 Excellent Security Posture
            </Typography>
            <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
              Your security score improved by {securityData.trend} points this week
            </Typography>
          </Box>
        </CardContent>
      </Card>
    </motion.div>
  );
};

export default SecurityPostureCard;
