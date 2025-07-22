import { useQuery } from '@tanstack/react-query'
import { Clock, User, Settings, AlertTriangle } from 'lucide-react'
import { adminApi } from '@/lib/api'
import { formatDistanceToNow } from 'date-fns'

export function RecentActivity() {
  const { data: auditData } = useQuery({
    queryKey: ['recent-audit'],
    queryFn: () => adminApi.getAuditHistory({ limit: 10 }),
    refetchInterval: 30000,
  })

  const activities = auditData?.data?.records || []

  const getActivityIcon = (eventType: string) => {
    switch (eventType) {
      case 'ConfigurationChange':
        return Settings
      case 'AdminOperation':
        return User
      case 'SecurityViolation':
        return AlertTriangle
      default:
        return Clock
    }
  }

  const getActivityColor = (outcome: string) => {
    switch (outcome) {
      case 'Success':
        return 'text-green-600'
      case 'Failure':
        return 'text-red-600'
      case 'Denied':
        return 'text-yellow-600'
      default:
        return 'text-gray-600'
    }
  }

  if (activities.length === 0) {
    return (
      <div className="text-center py-8">
        <Clock className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
        <p className="text-sm text-muted-foreground">No recent activity</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {activities.slice(0, 5).map((activity, index) => {
        const Icon = getActivityIcon(activity.event_type)
        return (
          <div key={index} className="flex items-start space-x-3">
            <div className={`flex-shrink-0 ${getActivityColor(activity.outcome)}`}>
              <Icon className="h-4 w-4" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-foreground truncate">
                {activity.action}
              </p>
              <p className="text-xs text-muted-foreground">
                {activity.user_id || 'System'} • {activity.resource}
              </p>
              <p className="text-xs text-muted-foreground">
                {formatDistanceToNow(new Date(activity.timestamp), { addSuffix: true })}
              </p>
            </div>
          </div>
        )
      })}
      
      {activities.length > 5 && (
        <div className="text-center pt-2">
          <button className="text-xs text-primary hover:underline">
            View all activity
          </button>
        </div>
      )}
    </div>
  )
}