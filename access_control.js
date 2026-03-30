/**
 * Access Control Module
 * Implements device ownership verification and Role-Based Access Control (RBAC)
 */

const { logger } = require('./security_middleware');

/**
 * User Roles and Permissions Model
 */
const ROLES = {
  admin: {
    description: 'Full system access',
    permissions: [
      'user:create',
      'user:read',
      'user:update',
      'user:delete',
      'user:manage-roles',
      'device:control',
      'device:config',
      'device:view-all',
      'schedule:manage',
      'logs:view',
      'settings:manage',
      'security:manage'
    ]
  },
  owner: {
    description: 'Own device management',
    permissions: [
      'device:control',
      'device:config',
      'device:view',
      'schedule:manage',
      'logs:view',
      'user:read'
    ]
  },
  user: {
    description: 'Limited device control',
    permissions: [
      'device:control',
      'device:view',
      'schedule:view'
    ]
  },
  guest: {
    description: 'View-only access',
    permissions: [
      'device:view',
      'schedule:view'
    ]
  }
};

/**
 * Check if user has permission
 * @param {Object} user - User object with role
 * @param {string} permission - Required permission
 * @returns {boolean} True if user has permission
 */
function hasPermission(user, permission) {
  if (!user || !user.role) return false;
  
  const role = ROLES[user.role];
  if (!role) {
    logger.warn(`Unknown role: ${user.role}`);
    return false;
  }
  
  return role.permissions.includes(permission);
}

/**
 * Check if user owns device
 * @param {Object} user - User object
 * @param {Object} device - Device object
 * @returns {boolean} True if user owns device
 */
function userOwnsDevice(user, device) {
  if (!user || !device) return false;
  
  // Admin can access all devices
  if (user.role === 'admin') return true;
  
  // Owner can only access their own devices
  return device.owner_id === user.id;
}

/**
 * Get devices accessible by user
 * @param {Object} user - User object
 * @param {Array} allDevices - All devices in system
 * @returns {Array} Filtered devices
 */
function getAccessibleDevices(user, allDevices = []) {
  if (!user) return [];
  
  // Admin sees all devices
  if (user.role === 'admin') return allDevices;
  
  // Owner sees only their devices
  if (user.role === 'owner') {
    return allDevices.filter(d => d.owner_id === user.id);
  }
  
  // User and guest see shared devices only (implement your sharing logic)
  return allDevices.filter(d => 
    d.owner_id === user.id || 
    (d.shared_with && d.shared_with.includes(user.id))
  );
}

/**
 * Check if action is allowed on device
 * @param {Object} user - User object
 * @param {Object} device - Device object
 * @param {string} action - Action name (control, config, view)
 * @returns {boolean} True if allowed
 */
function canPerformAction(user, device, action) {
  if (!user || !device) return false;
  
  // Check ownership
  if (!userOwnsDevice(user, device)) {
    logger.warn(`User ${user.username} attempted unauthorized action on device ${device.id}`);
    return false;
  }
  
  // Check permission for action
  const actionPermissionMap = {
    control: 'device:control',
    config: 'device:config',
    view: 'device:view',
    viewAll: 'device:view-all'
  };
  
  const requiredPermission = actionPermissionMap[action];
  if (!requiredPermission) {
    logger.error(`Unknown action: ${action}`);
    return false;
  }
  
  return hasPermission(user, requiredPermission);
}

/**
 * Middleware to check device ownership and permissions
 * @param {string} action - Action to check (control, config, view)
 * @returns {Function} Express middleware
 */
function requireDeviceAccess(action = 'view') {
  return (req, res, next) => {
    const deviceId = req.params.id;
    const data = req.app.locals.appData || { devices: [] };
    const device = data.devices.find(d => d.id === deviceId);
    
    if (!device) {
      return res.status(404).json({ error: 'Device not found' });
    }
    
    if (!canPerformAction(req.user, device, action)) {
      logger.warn(
        `Access denied: ${req.user.username} cannot ${action} device ${deviceId}`
      );
      return res.status(403).json({ 
        error: `You don't have permission to ${action} this device` 
      });
    }
    
    req.device = device;
    next();
  };
}

/**
 * Middleware to enforce role-based access
 * @param {...string} allowedRoles - Roles that can access
 * @returns {Function} Express middleware
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    if (!allowedRoles.includes(req.user.role)) {
      logger.warn(
        `Access denied: ${req.user.username} (${req.user.role}) attempted to access admin resource`
      );
      return res.status(403).json({ 
        error: 'Insufficient privileges for this action' 
      });
    }
    
    next();
  };
}

/**
 * Middleware to check specific permission
 * @param {string} permission - Required permission
 * @returns {Function} Express middleware
 */
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    if (!hasPermission(req.user, permission)) {
      logger.warn(
        `Permission denied: ${req.user.username} lacks permission '${permission}'`
      );
      return res.status(403).json({ 
        error: `Permission required: ${permission}` 
      });
    }
    
    next();
  };
}

/**
 * Share device with another user
 * @param {Object} device - Device object
 * @param {string} userId - User ID to share with
 * @returns {boolean} Success
 */
function shareDeviceWithUser(device, userId) {
  if (!device) return false;
  
  if (!device.shared_with) {
    device.shared_with = [];
  }
  
  if (!device.shared_with.includes(userId)) {
    device.shared_with.push(userId);
    logger.info(`Device ${device.id} shared with user ${userId}`);
    return true;
  }
  
  return false;
}

/**
 * Revoke device sharing with user
 * @param {Object} device - Device object
 * @param {string} userId - User ID to revoke access
 * @returns {boolean} Success
 */
function revokeDeviceShare(device, userId) {
  if (!device || !device.shared_with) return false;
  
  const index = device.shared_with.indexOf(userId);
  if (index > -1) {
    device.shared_with.splice(index, 1);
    logger.info(`Device ${device.id} access revoked for user ${userId}`);
    return true;
  }
  
  return false;
}

/**
 * Get all users with access to device
 * @param {Object} device - Device object
 * @returns {Array} User IDs with access
 */
function getDeviceAccessList(device) {
  if (!device) return [];
  
  return {
    owner_id: device.owner_id,
    shared_with: device.shared_with || []
  };
}

/**
 * Create audit log entry for access attempt
 * @param {Object} user - User object
 * @param {string} action - Action performed
 * @param {Object} device - Device object (optional)
 * @param {boolean} success - Whether action succeeded
 * @param {string} reason - Reason if denied
 * @returns {Object} Audit log entry
 */
function createAccessAuditLog(user, action, device = null, success = true, reason = null) {
  return {
    timestamp: new Date().toISOString(),
    userId: user?.id,
    username: user?.username,
    action,
    deviceId: device?.id,
    deviceName: device?.name,
    success,
    reason,
    ip: null // Will be populated by middleware
  };
}

module.exports = {
  // Constants
  ROLES,
  
  // Core functions
  hasPermission,
  userOwnsDevice,
  canPerformAction,
  getAccessibleDevices,
  
  // Middleware
  requireDeviceAccess,
  requireRole,
  requirePermission,
  
  // Sharing
  shareDeviceWithUser,
  revokeDeviceShare,
  getDeviceAccessList,
  
  // Audit
  createAccessAuditLog
};
