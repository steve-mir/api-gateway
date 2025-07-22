import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { AdminUser, UserFormData } from '@/types'
import { Button } from '@/components/ui/Button'

const userSchema = z.object({
  username: z.string().min(3, 'Username must be at least 3 characters'),
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters').optional(),
  roles: z.array(z.string()).min(1, 'At least one role is required'),
  active: z.boolean(),
})

interface UserFormProps {
  initialData?: AdminUser
  onSubmit: (data: UserFormData) => void
  onCancel: () => void
  isLoading?: boolean
}

const availableRoles = [
  { value: 'super_admin', label: 'Super Admin', description: 'Full system access' },
  { value: 'admin', label: 'Admin', description: 'Configuration and service management' },
  { value: 'operator', label: 'Operator', description: 'Service operations and monitoring' },
  { value: 'viewer', label: 'Viewer', description: 'Read-only access' },
]

export function UserForm({ initialData, onSubmit, onCancel, isLoading }: UserFormProps) {
  const {
    register,
    handleSubmit,
    formState: { errors },
    watch,
    setValue,
  } = useForm<UserFormData>({
    resolver: zodResolver(userSchema),
    defaultValues: {
      username: initialData?.username || '',
      email: initialData?.email || '',
      password: '',
      roles: initialData?.roles || [],
      active: initialData?.active ?? true,
    },
  })

  const selectedRoles = watch('roles')

  const handleRoleChange = (roleValue: string, checked: boolean) => {
    if (checked) {
      setValue('roles', [...selectedRoles, roleValue])
    } else {
      setValue('roles', selectedRoles.filter(role => role !== roleValue))
    }
  }

  const handleFormSubmit = (data: UserFormData) => {
    // Don't send password if it's empty for updates
    if (initialData && !data.password) {
      const { password, ...dataWithoutPassword } = data
      onSubmit(dataWithoutPassword as UserFormData)
    } else {
      onSubmit(data)
    }
  }

  return (
    <form onSubmit={handleSubmit(handleFormSubmit)} className="space-y-4">
      {/* Username */}
      <div>
        <label className="block text-sm font-medium mb-1">
          Username *
        </label>
        <input
          {...register('username')}
          type="text"
          className="w-full px-3 py-2 border border-input rounded-md bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          placeholder="admin"
        />
        {errors.username && (
          <p className="text-sm text-red-600 mt-1">{errors.username.message}</p>
        )}
      </div>

      {/* Email */}
      <div>
        <label className="block text-sm font-medium mb-1">
          Email *
        </label>
        <input
          {...register('email')}
          type="email"
          className="w-full px-3 py-2 border border-input rounded-md bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          placeholder="admin@example.com"
        />
        {errors.email && (
          <p className="text-sm text-red-600 mt-1">{errors.email.message}</p>
        )}
      </div>

      {/* Password */}
      <div>
        <label className="block text-sm font-medium mb-1">
          Password {!initialData && '*'}
        </label>
        <input
          {...register('password')}
          type="password"
          className="w-full px-3 py-2 border border-input rounded-md bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          placeholder={initialData ? 'Leave blank to keep current password' : 'Enter password'}
        />
        {errors.password && (
          <p className="text-sm text-red-600 mt-1">{errors.password.message}</p>
        )}
      </div>

      {/* Roles */}
      <div>
        <label className="block text-sm font-medium mb-2">
          Roles *
        </label>
        <div className="space-y-2">
          {availableRoles.map((role) => (
            <div key={role.value} className="flex items-start space-x-3">
              <input
                type="checkbox"
                id={role.value}
                checked={selectedRoles.includes(role.value)}
                onChange={(e) => handleRoleChange(role.value, e.target.checked)}
                className="mt-1 rounded border-input"
              />
              <div className="flex-1">
                <label htmlFor={role.value} className="text-sm font-medium cursor-pointer">
                  {role.label}
                </label>
                <p className="text-xs text-muted-foreground">{role.description}</p>
              </div>
            </div>
          ))}
        </div>
        {errors.roles && (
          <p className="text-sm text-red-600 mt-1">{errors.roles.message}</p>
        )}
      </div>

      {/* Active Status */}
      <div className="flex items-center space-x-2">
        <input
          {...register('active')}
          type="checkbox"
          id="active"
          className="rounded border-input"
        />
        <label htmlFor="active" className="text-sm font-medium">
          Active user account
        </label>
      </div>

      {/* Role Warnings */}
      {selectedRoles.includes('super_admin') && (
        <div className="p-3 bg-yellow-50 border border-yellow-200 rounded-md">
          <p className="text-sm text-yellow-800">
            <strong>Warning:</strong> Super Admin role grants full system access including user management.
          </p>
        </div>
      )}

      {/* Actions */}
      <div className="flex justify-end space-x-2 pt-4">
        <Button
          type="button"
          variant="outline"
          onClick={onCancel}
          disabled={isLoading}
        >
          Cancel
        </Button>
        <Button
          type="submit"
          disabled={isLoading}
        >
          {isLoading ? 'Saving...' : initialData ? 'Update User' : 'Create User'}
        </Button>
      </div>
    </form>
  )
}