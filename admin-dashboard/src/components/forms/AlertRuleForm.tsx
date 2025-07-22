import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { AlertRule, AlertCondition, AlertRuleFormData } from '@/types'
import { Button } from '@/components/ui/Button'

const alertRuleSchema = z.object({
  name: z.string().min(1, 'Alert name is required'),
  description: z.string().optional(),
  metric_name: z.string().min(1, 'Metric name is required'),
  condition: z.nativeEnum(AlertCondition),
  threshold: z.number().min(0, 'Threshold must be positive'),
  duration_seconds: z.number().min(1, 'Duration must be at least 1 second'),
})

interface AlertRuleFormProps {
  initialData?: AlertRule
  onSubmit: (data: AlertRuleFormData) => void
  onCancel: () => void
  isLoading?: boolean
}

export function AlertRuleForm({ initialData, onSubmit, onCancel, isLoading }: AlertRuleFormProps) {
  const [labels, setLabels] = useState<Record<string, string>>(
    initialData?.labels || {}
  )

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<AlertRuleFormData>({
    resolver: zodResolver(alertRuleSchema),
    defaultValues: {
      name: initialData?.name || '',
      description: initialData?.description || '',
      metric_name: initialData?.metric_name || '',
      condition: initialData?.condition || AlertCondition.GreaterThan,
      threshold: initialData?.threshold || 0,
      duration_seconds: initialData?.duration ? initialData.duration / 1000 : 60,
    },
  })

  const handleFormSubmit = (data: AlertRuleFormData) => {
    onSubmit({
      ...data,
      labels,
    })
  }

  const addLabel = () => {
    const key = prompt('Enter label key:')
    if (key && !labels[key]) {
      setLabels({ ...labels, [key]: '' })
    }
  }

  const updateLabelValue = (key: string, value: string) => {
    setLabels({ ...labels, [key]: value })
  }

  const removeLabel = (key: string) => {
    const newLabels = { ...labels }
    delete newLabels[key]
    setLabels(newLabels)
  }

  return (
    <form onSubmit={handleSubmit(handleFormSubmit)} className="space-y-4">
      {/* Alert Name */}
      <div>
        <label className="block text-sm font-medium mb-1">
          Alert Name *
        </label>
        <input
          {...register('name')}
          type="text"
          className="w-full px-3 py-2 border border-input rounded-md bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          placeholder="High Error Rate"
        />
        {errors.name && (
          <p className="text-sm text-red-600 mt-1">{errors.name.message}</p>
        )}
      </div>

      {/* Description */}
      <div>
        <label className="block text-sm font-medium mb-1">
          Description
        </label>
        <textarea
          {...register('description')}
          rows={2}
          className="w-full px-3 py-2 border border-input rounded-md bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          placeholder="Alert when error rate exceeds threshold"
        />
      </div>

      {/* Metric Name */}
      <div>
        <label className="block text-sm font-medium mb-1">
          Metric Name *
        </label>
        <select
          {...register('metric_name')}
          className="w-full px-3 py-2 border border-input rounded-md bg-background text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
        >
          <option value="">Select a metric</option>
          <option value="error_rate">Error Rate</option>
          <option value="response_time">Response Time</option>
          <option value="request_count">Request Count</option>
          <option value="cpu_usage">CPU Usage</option>
          <option value="memory_usage">Memory Usage</option>
          <option value="active_connections">Active Connections</option>
        </select>
        {errors.metric_name && (
          <p className="text-sm text-red-600 mt-1">{errors.metric_name.message}</p>
        )}
      </div>

      {/* Condition and Threshold */}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium mb-1">
            Condition *
          </label>
          <select
            {...register('condition')}
            className="w-full px-3 py-2 border border-input rounded-md bg-background text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          >
            <option value={AlertCondition.GreaterThan}>Greater Than</option>
            <option value={AlertCondition.LessThan}>Less Than</option>
            <option value={AlertCondition.GreaterThanOrEqual}>Greater Than or Equal</option>
            <option value={AlertCondition.LessThanOrEqual}>Less Than or Equal</option>
            <option value={AlertCondition.Equal}>Equal</option>
            <option value={AlertCondition.NotEqual}>Not Equal</option>
          </select>
          {errors.condition && (
            <p className="text-sm text-red-600 mt-1">{errors.condition.message}</p>
          )}
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">
            Threshold *
          </label>
          <input
            {...register('threshold', { valueAsNumber: true })}
            type="number"
            step="0.01"
            className="w-full px-3 py-2 border border-input rounded-md bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
            placeholder="0.05"
          />
          {errors.threshold && (
            <p className="text-sm text-red-600 mt-1">{errors.threshold.message}</p>
          )}
        </div>
      </div>

      {/* Duration */}
      <div>
        <label className="block text-sm font-medium mb-1">
          Duration (seconds) *
        </label>
        <input
          {...register('duration_seconds', { valueAsNumber: true })}
          type="number"
          min="1"
          className="w-full px-3 py-2 border border-input rounded-md bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          placeholder="60"
        />
        <p className="text-xs text-muted-foreground mt-1">
          How long the condition must be true before triggering the alert
        </p>
        {errors.duration_seconds && (
          <p className="text-sm text-red-600 mt-1">{errors.duration_seconds.message}</p>
        )}
      </div>

      {/* Labels */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="block text-sm font-medium">
            Labels
          </label>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={addLabel}
          >
            Add Label
          </Button>
        </div>
        <div className="space-y-2">
          {Object.entries(labels).map(([key, value]) => (
            <div key={key} className="flex gap-2">
              <input
                type="text"
                value={key}
                disabled
                className="flex-1 px-3 py-2 border border-input rounded-md bg-muted text-foreground"
              />
              <input
                type="text"
                value={value}
                onChange={(e) => updateLabelValue(key, e.target.value)}
                className="flex-1 px-3 py-2 border border-input rounded-md bg-background text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="Value"
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => removeLabel(key)}
              >
                Remove
              </Button>
            </div>
          ))}
          {Object.keys(labels).length === 0 && (
            <p className="text-sm text-muted-foreground">No labels configured</p>
          )}
        </div>
      </div>

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
          {isLoading ? 'Saving...' : initialData ? 'Update Alert' : 'Create Alert'}
        </Button>
      </div>
    </form>
  )
}