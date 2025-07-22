import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { ServiceInstance, ServiceFormData } from '@/types'
import { Button } from '@/components/ui/Button'

const serviceSchema = z.object({
  name: z.string().min(1, 'Service name is required'),
  address: z.string().min(1, 'Address is required'),
  protocol: z.enum(['http', 'grpc', 'websocket']),
  weight: z.number().min(1).max(100),
  persist: z.boolean(),
})

interface ServiceFormProps {
  initialData?: ServiceInstance
  onSubmit: (data: ServiceFormData) => void
  onCancel: () => void
  isLoading?: boolean
}

export function ServiceForm({ initialData, onSubmit, onCancel, isLoading }: ServiceFormProps) {
  const [metadata, setMetadata] = useState<Record<string, string>>(
    initialData?.metadata || {}
  )

  const {
    register,
    handleSubmit,
    formState: { errors },
    setValue,
    watch,
  } = useForm<ServiceFormData>({
    resolver: zodResolver(serviceSchema),
    defaultValues: {
      name: initialData?.name || '',
      address: initialData?.address || '',
      protocol: (initialData?.protocol as any) || 'http',
      weight: initialData?.weight || 1,
      persist: true,
    },
  })

  const handleFormSubmit = (data: ServiceFormData) => {
    onSubmit({
      ...data,
      metadata,
    })
  }

  const addMetadataField = () => {
    const key = prompt('Enter metadata key:')
    if (key && !metadata[key]) {
      setMetadata({ ...metadata, [key]: '' })
    }
  }

  const updateMetadataValue = (key: string, value: string) => {
    setMetadata({ ...metadata, [key]: value })
  }

  const removeMetadataField = (key: string) => {
    const newMetadata = { ...metadata }
    delete newMetadata[key]
    setMetadata(newMetadata)
  }

  return (
    <form onSubmit={handleSubmit(handleFormSubmit)} className="space-y-4">
      {/* Service Name */}
      <div>
        <label className="block text-sm font-medium mb-1">
          Service Name *
        </label>
        <input
          {...register('name')}
          type="text"
          className="w-full px-3 py-2 border border-input rounded-md bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          placeholder="my-service"
        />
        {errors.name && (
          <p className="text-sm text-red-600 mt-1">{errors.name.message}</p>
        )}
      </div>

      {/* Address */}
      <div>
        <label className="block text-sm font-medium mb-1">
          Address *
        </label>
        <input
          {...register('address')}
          type="text"
          className="w-full px-3 py-2 border border-input rounded-md bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          placeholder="localhost:8080"
        />
        {errors.address && (
          <p className="text-sm text-red-600 mt-1">{errors.address.message}</p>
        )}
      </div>

      {/* Protocol */}
      <div>
        <label className="block text-sm font-medium mb-1">
          Protocol *
        </label>
        <select
          {...register('protocol')}
          className="w-full px-3 py-2 border border-input rounded-md bg-background text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
        >
          <option value="http">HTTP</option>
          <option value="grpc">gRPC</option>
          <option value="websocket">WebSocket</option>
        </select>
        {errors.protocol && (
          <p className="text-sm text-red-600 mt-1">{errors.protocol.message}</p>
        )}
      </div>

      {/* Weight */}
      <div>
        <label className="block text-sm font-medium mb-1">
          Weight
        </label>
        <input
          {...register('weight', { valueAsNumber: true })}
          type="number"
          min="1"
          max="100"
          className="w-full px-3 py-2 border border-input rounded-md bg-background text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
        />
        {errors.weight && (
          <p className="text-sm text-red-600 mt-1">{errors.weight.message}</p>
        )}
      </div>

      {/* Metadata */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="block text-sm font-medium">
            Metadata
          </label>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={addMetadataField}
          >
            Add Field
          </Button>
        </div>
        <div className="space-y-2">
          {Object.entries(metadata).map(([key, value]) => (
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
                onChange={(e) => updateMetadataValue(key, e.target.value)}
                className="flex-1 px-3 py-2 border border-input rounded-md bg-background text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                placeholder="Value"
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => removeMetadataField(key)}
              >
                Remove
              </Button>
            </div>
          ))}
        </div>
      </div>

      {/* Persist */}
      <div className="flex items-center space-x-2">
        <input
          {...register('persist')}
          type="checkbox"
          id="persist"
          className="rounded border-input"
        />
        <label htmlFor="persist" className="text-sm font-medium">
          Persist service configuration
        </label>
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
          {isLoading ? 'Saving...' : initialData ? 'Update Service' : 'Create Service'}
        </Button>
      </div>
    </form>
  )
}