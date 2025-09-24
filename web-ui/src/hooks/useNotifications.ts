import { useState, useEffect } from 'react';

export interface Notification {
  id: string;
  title: string;
  message: string;
  type: 'info' | 'warning' | 'error' | 'success';
  timestamp: Date;
  read: boolean;
}

export const useNotifications = () => {
  const [notifications, setNotifications] = useState<Notification[]>([
    {
      id: '1',
      title: 'Security Alert',
      message: 'High-risk vulnerability detected in production cluster',
      type: 'error',
      timestamp: new Date(Date.now() - 5 * 60 * 1000),
      read: false,
    },
    {
      id: '2',
      title: 'Compliance Update',
      message: 'SOC2 audit completed successfully',
      type: 'success',
      timestamp: new Date(Date.now() - 30 * 60 * 1000),
      read: false,
    },
    {
      id: '3',
      title: 'System Update',
      message: 'Fortress platform updated to v3.1',
      type: 'info',
      timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000),
      read: true,
    },
  ]);

  const unreadCount = notifications.filter((n) => !n.read).length;

  const markAsRead = (id: string) => {
    setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, read: true } : n)));
  };

  const markAllAsRead = () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  };

  const addNotification = (notification: Omit<Notification, 'id' | 'timestamp' | 'read'>) => {
    const newNotification: Notification = {
      ...notification,
      id: Date.now().toString(),
      timestamp: new Date(),
      read: false,
    };
    setNotifications((prev) => [newNotification, ...prev]);
  };

  const removeNotification = (id: string) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  };

  return {
    notifications,
    unreadCount,
    markAsRead,
    markAllAsRead,
    addNotification,
    removeNotification,
  };
};
