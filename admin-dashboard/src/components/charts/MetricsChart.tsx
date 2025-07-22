import { useQuery } from '@tanstack/react-query'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { adminApi } from '@/lib/api'

// Generate mock data for demonstration
const generateMockData = () => {
  const now = Date.now()
  const data = []
  
  for (let i = 23; i >= 0; i--) {
    const timestamp = now - (i * 60 * 1000) // Every minute for last 24 minutes
    data.push({
      time: new Date(timestamp).toLocaleTimeString('en-US', { 
        hour12: false, 
        hour: '2-digit', 
        minute: '2-digit' 
      }),
      requests: Math.floor(Math.random() * 100) + 50,
      errors: Math.floor(Math.random() * 10) + 1,
      responseTime: Math.floor(Math.random() * 200) + 100,
    })
  }
  
  return data
}

export function MetricsChart() {
  const { data: metricsData } = useQuery({
    queryKey: ['metrics-chart'],
    queryFn: async () => {
      // In a real implementation, this would query actual metrics data
      // For now, we'll use mock data
      return { data: generateMockData() }
    },
    refetchInterval: 15000, // Refresh every 15 seconds
  })

  const data = metricsData?.data || []

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
          <XAxis 
            dataKey="time" 
            className="text-xs fill-muted-foreground"
            tick={{ fontSize: 12 }}
          />
          <YAxis 
            className="text-xs fill-muted-foreground"
            tick={{ fontSize: 12 }}
          />
          <Tooltip 
            contentStyle={{
              backgroundColor: 'hsl(var(--card))',
              border: '1px solid hsl(var(--border))',
              borderRadius: '6px',
              color: 'hsl(var(--card-foreground))',
            }}
          />
          <Line 
            type="monotone" 
            dataKey="requests" 
            stroke="hsl(var(--primary))" 
            strokeWidth={2}
            dot={false}
            name="Requests/min"
          />
          <Line 
            type="monotone" 
            dataKey="errors" 
            stroke="#ef4444" 
            strokeWidth={2}
            dot={false}
            name="Errors/min"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}