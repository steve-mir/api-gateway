import { useState } from 'react'
import { 
  Plus, 
  Search, 
  Filter, 
  Edit, 
  Trash2, 
  UserCheck, 
  UserX, 
  Shield,
  Key,
  Calendar
} from 'lucide-react'
import { AdminUser } from '@/types'
import { Card } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Modal } from '@/components/ui/Modal'
import { UserForm } from '@/components/forms/UserForm'

// Mock data for demonstration
const mockUsers: AdminUser[] = [
  {
    id: '1',
    username: 'admin',
    email: 'admin@example.com',
    roles: ['super_admin'],
    permissions: ['*'],
    created_at: '2024-01-01T00:00:00Z',
    last_login: '2024-01-15T10:30:00Z',
    active: true,
  },
  {
    id: '2',
    username: 'operator',
    email: 'operator@example.com',
    roles: ['operator'],
    permissions: ['read', 'services:manage', 'metrics:read'],
    created_at: '2024-01-05T00:00:00Z',
    last_login: '2024-01-14T15:45:00Z',
    active: true,
  },
  {
    id: '3',
    username: 'viewer',
    email: 'viewer@example.com',
    roles: ['viewer'],
    permissions: ['read'],
    created_at: '2024-01-10T00:00:00Z',
    last_login: '2024-01-12T09:15:00Z',
    active: true,
  },
  {
    id: '4',
    username: 'disabled_user',
    email: 'disabled@example.com',
    roles: ['viewer'],
    permissions: ['read'],
    created_at: '2024-01-08T00:00:00Z',
    active: false,
  },
]

export function Users() {
  const [users] = useState<AdminUser[]>(mockUsers)
  const [searchTerm, setSearchTerm] = useState('')
  const [roleFilter, setRoleFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingUser, setEditingUser] = useState<AdminUser | null>(null)
  const [selectedUsers, setSelectedUsers] = useState<string[]>([])

  const filteredUsers = users.filter(user => {
    const matchesSearch = user.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.email.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesRole = roleFilter === 'all' || user.roles.includes(roleFilter)
    const matchesStatus = statusFilter === 'all' || 
                         (statusFilter === 'active' && user.active) ||
                         (statusFilter === 'inactive' && !user.active)
    
    return matchesSearch && matchesRole && matchesStatus
  })

  const activeUsers = users.filter(user => user.active).length
  const totalUsers = users.length
  const recentLogins = users.filter(user => 
    user.last_login && 
    new Date(user.last_login).getTime() > Date.now() - 24 * 60 * 60 * 1000
  ).length

  const handleCreateUser = (data: any) => {
    console.log('Creating user:', data)
    setShowCreateModal(false)
  }

  const handleUpdateUser = (data: any) => {
    console.log('Updating user:', data)
    setEditingUser(null)
  }

  const handleDeleteUser = (userId: string) => {
    if (confirm('Are you sure you want to delete this user?')) {
      console.log('Deleting user:', userId)
    }
  }

  const handleToggleUserStatus = (userId: string) => {
    console.log('Toggling user status:', userId)
  }

  const getRoleBadgeColor = (role: string) => {
    switch (role) {
      case 'super_admin':
        return 'bg-red-100 text-red-800 border-red-200'
      case 'admin':
        return 'bg-purple-100 text-purple-800 border-purple-200'
      case 'operator':
        return 'bg-blue-100 text-blue-800 border-blue-200'
      case 'viewer':
        return 'bg-green-100 text-green-800 border-green-200'
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">User Management</h1>
          <p className="text-muted-foreground">
            Manage admin users and their permissions
          </p>
        </div>
        <Button onClick={() => setShowCreateModal(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Add User
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="p-4">
          <div className="flex items-center">
            <Shield className="h-8 w-8 text-blue-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-muted-foreground">Total Users</p>
              <p className="text-2xl font-bold">{totalUsers}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center">
            <UserCheck className="h-8 w-8 text-green-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-muted-foreground">Active Users</p>
              <p className="text-2xl font-bold">{activeUsers}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center">
            <UserX className="h-8 w-8 text-red-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-muted-foreground">Inactive Users</p>
              <p className="text-2xl font-bold">{totalUsers - activeUsers}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center">
            <Calendar className="h-8 w-8 text-purple-600" />
            <div className="ml-4">
              <p className="text-sm font-medium text-muted-foreground">Recent Logins</p>
              <p className="text-2xl font-bold">{recentLogins}</p>
            </div>
          </div>
        </Card>
      </div>

      {/* Filters and Search */}
      <Card className="p-4">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search users..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-input rounded-md bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
              />
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <select
              value={roleFilter}
              onChange={(e) => setRoleFilter(e.target.value)}
              className="px-3 py-2 border border-input rounded-md bg-background text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
            >
              <option value="all">All Roles</option>
              <option value="super_admin">Super Admin</option>
              <option value="admin">Admin</option>
              <option value="operator">Operator</option>
              <option value="viewer">Viewer</option>
            </select>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-2 border border-input rounded-md bg-background text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
            >
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Users Table */}
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">
                  <input
                    type="checkbox"
                    className="rounded border-input"
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedUsers(filteredUsers.map(u => u.id))
                      } else {
                        setSelectedUsers([])
                      }
                    }}
                  />
                </th>
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">Status</th>
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">User</th>
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">Roles</th>
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">Last Login</th>
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">Created</th>
                <th className="text-left py-3 px-4 font-medium text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredUsers.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-muted-foreground">
                    No users found
                  </td>
                </tr>
              ) : (
                filteredUsers.map((user) => (
                  <tr key={user.id} className="border-b border-border hover:bg-muted/50">
                    <td className="py-3 px-4">
                      <input
                        type="checkbox"
                        className="rounded border-input"
                        checked={selectedUsers.includes(user.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedUsers([...selectedUsers, user.id])
                          } else {
                            setSelectedUsers(selectedUsers.filter(id => id !== user.id))
                          }
                        }}
                      />
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        {user.active ? (
                          <UserCheck className="h-4 w-4 text-green-600" />
                        ) : (
                          <UserX className="h-4 w-4 text-red-600" />
                        )}
                        <span className={`px-2 py-1 text-xs font-medium rounded-full border ${
                          user.active 
                            ? 'bg-green-100 text-green-800 border-green-200' 
                            : 'bg-red-100 text-red-800 border-red-200'
                        }`}>
                          {user.active ? 'Active' : 'Inactive'}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <div>
                        <div className="font-medium">{user.username}</div>
                        <div className="text-sm text-muted-foreground">{user.email}</div>
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1">
                        {user.roles.map((role) => (
                          <span
                            key={role}
                            className={`px-2 py-1 text-xs font-medium rounded border ${getRoleBadgeColor(role)}`}
                          >
                            {role.replace('_', ' ')}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-sm">
                      {user.last_login ? (
                        new Date(user.last_login).toLocaleDateString()
                      ) : (
                        <span className="text-muted-foreground">Never</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-sm">
                      {new Date(user.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleToggleUserStatus(user.id)}
                          className="p-1 hover:bg-muted rounded"
                          title={user.active ? 'Deactivate user' : 'Activate user'}
                        >
                          {user.active ? (
                            <UserX className="h-4 w-4" />
                          ) : (
                            <UserCheck className="h-4 w-4" />
                          )}
                        </button>
                        <button
                          onClick={() => setEditingUser(user)}
                          className="p-1 hover:bg-muted rounded"
                          title="Edit user"
                        >
                          <Edit className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteUser(user.id)}
                          className="p-1 hover:bg-muted rounded text-red-600"
                          title="Delete user"
                          disabled={user.roles.includes('super_admin')}
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Role Permissions Reference */}
      <Card className="p-6">
        <h3 className="text-lg font-medium mb-4">Role Permissions Reference</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="space-y-2">
            <div className={`px-3 py-2 rounded border ${getRoleBadgeColor('super_admin')}`}>
              <div className="font-medium">Super Admin</div>
            </div>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Full system access</li>
              <li>• User management</li>
              <li>• System configuration</li>
              <li>• All operations</li>
            </ul>
          </div>
          <div className="space-y-2">
            <div className={`px-3 py-2 rounded border ${getRoleBadgeColor('admin')}`}>
              <div className="font-medium">Admin</div>
            </div>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Configuration management</li>
              <li>• Service management</li>
              <li>• Metrics and logs</li>
              <li>• Alert management</li>
            </ul>
          </div>
          <div className="space-y-2">
            <div className={`px-3 py-2 rounded border ${getRoleBadgeColor('operator')}`}>
              <div className="font-medium">Operator</div>
            </div>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Service operations</li>
              <li>• Health monitoring</li>
              <li>• Basic configuration</li>
              <li>• Metrics viewing</li>
            </ul>
          </div>
          <div className="space-y-2">
            <div className={`px-3 py-2 rounded border ${getRoleBadgeColor('viewer')}`}>
              <div className="font-medium">Viewer</div>
            </div>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Read-only access</li>
              <li>• View metrics</li>
              <li>• View logs</li>
              <li>• View configuration</li>
            </ul>
          </div>
        </div>
      </Card>

      {/* Create User Modal */}
      <Modal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Add New User"
      >
        <UserForm
          onSubmit={handleCreateUser}
          onCancel={() => setShowCreateModal(false)}
        />
      </Modal>

      {/* Edit User Modal */}
      <Modal
        isOpen={!!editingUser}
        onClose={() => setEditingUser(null)}
        title="Edit User"
      >
        {editingUser && (
          <UserForm
            initialData={editingUser}
            onSubmit={handleUpdateUser}
            onCancel={() => setEditingUser(null)}
          />
        )}
      </Modal>
    </div>
  )
}