import { useState, useEffect } from 'react';
import ContentLayout from '@cloudscape-design/components/content-layout';
import Header from '@cloudscape-design/components/header';
import Container from '@cloudscape-design/components/container';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Slider from '@cloudscape-design/components/slider';
import Table from '@cloudscape-design/components/table';
import Grid from '@cloudscape-design/components/grid';
import ColumnLayout from '@cloudscape-design/components/column-layout';
import Box from '@cloudscape-design/components/box';
import Badge from '@cloudscape-design/components/badge';
import Button from '@cloudscape-design/components/button';
import axios from 'axios';
import { getTimeline } from '../services/api';

import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

export default function ForensicTimeline() {
  const [history, setHistory] = useState([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [trends, setTrends] = useState([]);
  const [selectedItems, setSelectedItems] = useState([]);
  const [comparisonReport, setComparisonReport] = useState(null);

  useEffect(() => {
    // 1. Fetch historical completed scans
    getTimeline().then(data => {
      setHistory(data || []);
      setCurrentIndex(Math.max(0, data.length - 1));
    });

    // 2. Fetch aggregate trends for chart
    axios.get('http://localhost:4000/api/forensics/trends')
      .then(res => setTrends(res.data || []))
      .catch(e => console.error(e));
  }, []);

  const currentSnapshot = history[currentIndex] || {};

  const handleCompare = () => {
    if (selectedItems.length !== 2) return;
    const a = selectedItems[0].scan_id;
    const b = selectedItems[1].scan_id;
    axios.get(`http://localhost:4000/api/forensics/compare?a=${a}&b=${b}`)
      .then(res => setComparisonReport(res.data))
      .catch(e => console.error(e));
  };

  return (
    <ContentLayout header={<Header variant="h1" description="Historical infrastructure state · asset volume and risk trajectory over time">Infrastructure Asset Timeline</Header>}>
      <SpaceBetween size="l">
        <Grid gridDefinition={[{ colspan: 8 }, { colspan: 4 }]}>
          <Container header={<Header variant="h2">Historical Infrastructure Health Trajectory</Header>}>
            <SpaceBetween size="m">
              <div style={{ height: '300px', width: '100%' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={trends}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#444" />
                    <XAxis dataKey="timestamp" hide />
                    <YAxis yAxisId="left" stroke="#0073bb" label={{ value: 'Assets', angle: -90, position: 'insideLeft', fill: '#0073bb' }} />
                    <YAxis yAxisId="right" orientation="right" stroke="#ef4444" label={{ value: 'Risk', angle: 90, position: 'insideRight', fill: '#ef4444' }} />
                    <Tooltip contentStyle={{ backgroundColor: '#222', borderColor: '#444' }} />
                    <Legend />
                    <Line yAxisId="left" type="monotone" dataKey="assets" stroke="#0073bb" strokeWidth={3} dot={{ r: 4 }} name="Total Assets" />
                    <Line yAxisId="right" type="monotone" dataKey="risk" stroke="#ef4444" strokeWidth={3} dot={{ r: 4 }} name="Aggregate Risk" />
                  </LineChart>
                </ResponsiveContainer>
              </div>
              <Slider
                max={Math.max(0, history.length - 1)}
                min={0}
                value={currentIndex}
                onChange={({ detail }) => setCurrentIndex(detail.value)}
                valueFormatter={(val) => history[val] ? new Date(history[val].timestamp).toLocaleString() : ''}
              />
            </SpaceBetween>
          </Container>

          <Container header={<Header variant="h2">Snapshot Metrics</Header>}>
            <ColumnLayout columns={1}>
              <div>
                <Box variant="small" color="text-status-inactive">Total Live Assets</Box>
                <Box variant="h2">{currentSnapshot.node_count || 0}</Box>
              </div>
              <div>
                <Box variant="small" color="text-status-inactive">Aggregate Risk</Box>
                <Box variant="h2" color={currentSnapshot.risk_summary > 70 ? 'text-status-error' : 'text-status-success'}>
                  {currentSnapshot.risk_summary?.toFixed(2) || '0.00'}
                </Box>
              </div>
            </ColumnLayout>
          </Container>
        </Grid>

        {/* Comparison Result Section */}
        {comparisonReport && (
          <Container header={<Header variant="h2" actions={<Button onClick={() => setComparisonReport(null)}>Clear</Button>}>Infrastructure Delta Report</Header>}>
            <Grid gridDefinition={[{ colspan: 4 }, { colspan: 4 }, { colspan: 4 }]}>
              <div>
                <Box variant="h3" color="text-status-success">Added ({comparisonReport.delta.summary.added_count})</Box>
                <ul style={{ fontSize: '12px' }}>
                  {comparisonReport.delta.deltas.added.map(id => <li key={id}>{id}</li>)}
                </ul>
              </div>
              <div>
                <Box variant="h3" color="text-status-error">Removed ({comparisonReport.delta.summary.removed_count})</Box>
                <ul style={{ fontSize: '12px' }}>
                  {comparisonReport.delta.deltas.removed.map(id => <li key={id}>{id}</li>)}
                </ul>
              </div>
              <div>
                <Box variant="h3" color="text-status-warning">Modified ({comparisonReport.delta.summary.modified_count})</Box>
                <ul style={{ fontSize: '12px' }}>
                  {Object.keys(comparisonReport.delta.deltas.modified).map(id => <li key={id}>{id}</li>)}
                </ul>
              </div>
            </Grid>
          </Container>
        )}

        <Container header={<Header variant="h2" actions={<Button disabled={selectedItems.length !== 2} onClick={handleCompare}>Compare Selected (2)</Button>}>Detailed Audit Trail</Header>}>
          <Table
            columnDefinitions={[
              { id: 'timestamp', header: 'Snapshot Time', cell: e => new Date(e.timestamp).toLocaleString() },
              { id: 'scan_id', header: 'Scan Fingerprint', cell: e => e.scan_id },
              { id: 'status', header: 'Status', cell: e => <Badge color="green">IMMUTABLE</Badge> },
              { id: 'nodes', header: 'Assets', cell: e => e.node_count }
            ]}
            items={history.slice().reverse()}
            onSelectionChange={({ detail }) => setSelectedItems(detail.selectedItems)}
            selectedItems={selectedItems}
            selectionType="multi"
            trackBy="scan_id"
            empty="Awaiting historical snapshots..."
          />
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
