import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

type TrendPoint = { time: string; observed: number; detections: number };

export default function DashboardActivityChart({ trend }: { trend: TrendPoint[] }) {
  return <ResponsiveContainer width="100%" height="100%">
    <AreaChart data={trend} margin={{ top: 12, right: 6, bottom: 0, left: -15 }}>
      <defs>
        <linearGradient id="eventFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#80d85f" stopOpacity={0.19} /><stop offset="95%" stopColor="#80d85f" stopOpacity={0} /></linearGradient>
        <linearGradient id="detectionFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#f18b69" stopOpacity={0.16} /><stop offset="95%" stopColor="#f18b69" stopOpacity={0} /></linearGradient>
      </defs>
      <CartesianGrid stroke="rgba(201,221,210,.07)" vertical={false} />
      <XAxis dataKey="time" tickFormatter={(value: string) => new Date(value).toLocaleTimeString([], { hour: 'numeric' })} axisLine={false} tickLine={false} tick={{ fill: '#718078', fontSize: 10 }} dy={10} minTickGap={30} />
      <YAxis axisLine={false} tickLine={false} tick={{ fill: '#718078', fontSize: 10 }} />
      <Tooltip content={<ChartTooltip />} />
      <Area type="monotone" dataKey="observed" name="Observed events" stroke="#85d963" strokeWidth={2} fill="url(#eventFill)" activeDot={{ r: 4, fill: '#a3eb81', stroke: '#172019', strokeWidth: 2 }} />
      <Area type="monotone" dataKey="detections" name="Detections" stroke="#ef8a68" strokeWidth={2} fill="url(#detectionFill)" activeDot={{ r: 4, fill: '#ffad8d', stroke: '#251814', strokeWidth: 2 }} />
    </AreaChart>
  </ResponsiveContainer>;
}

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: { name?: string; value?: number; color?: string }[]; label?: string }) {
  if (!active || !payload?.length) return null;
  return <div className="chart-tooltip"><strong>{label ? new Date(label).toLocaleString([], { weekday: 'short', hour: 'numeric' }) : ''}</strong>{payload.map((item) => <span key={item.name}><i style={{ background: item.color }} />{item.name}<b>{item.value}</b></span>)}</div>;
}
