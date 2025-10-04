import React, { useEffect, useState } from "react";
import { Bell } from "lucide-react";

const AuditLogsView = () => {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    // Simulated data fetching for audit logs
    const fetchLogs = async () => {
      const mockLogs = [
        { id: 1, message: "User logged in", severity: "info", timestamp: "2025-10-04 12:10:00" },
        { id: 2, message: "User updated profile", severity: "warning", timestamp: "2025-10-04 12:30:00" },
        { id: 3, message: "Critical system error", severity: "critical", timestamp: "2025-10-04 12:45:00" },
      ];
      setLogs(mockLogs);
    };

    fetchLogs();
  }, []);

  return (
    <div className="p-8 bg-gray-50 min-h-screen">
      {/* Header Section */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-800">Audit Logs Dashboard</h1>
        <p className="text-gray-600">Track and analyze system audit logs in real time.</p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
        <div className="bg-blue-50 p-4 rounded-lg">
          <p className="text-sm text-blue-600">Total Logs</p>
          <p className="text-2xl font-bold text-blue-900">{logs.length}</p>
        </div>

        <div className="bg-yellow-50 p-4 rounded-lg">
          <p className="text-sm text-yellow-600">Warnings</p>
          <p className="text-2xl font-bold text-yellow-900">
            {logs.filter((log) => log.severity === "warning").length}
          </p>
        </div>

        <div className="bg-red-50 p-4 rounded-lg">
          <p className="text-sm text-red-600">Critical Issues</p>
          <p className="text-2xl font-bold text-red-900">
            {logs.filter((log) => log.severity === "critical").length}
          </p>
        </div>
      </div>

      {/* Notification Section */}
      <div className="bg-green-50 p-4 rounded-lg">
        <div className="flex items-center">
          <Bell className="w-8 h-8 text-green-600" />
          <div className="ml-3">
            <p className="text-lg font-semibold text-green-800">Live Notifications</p>
            <p className="text-sm text-green-600">
              Real-time alerts about critical system events.
            </p>
          </div>
        </div>
      </div>

      {/* Logs Table */}
      <div className="mt-10">
        <h2 className="text-xl font-semibold mb-4 text-gray-800">Recent Logs</h2>
        <div className="bg-white shadow rounded-lg overflow-hidden">
          <table className="min-w-full text-left border-collapse">
            <thead>
              <tr className="bg-gray-100 text-gray-700 uppercase text-sm">
                <th className="px-4 py-3">ID</th>
                <th className="px-4 py-3">Message</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id} className="border-b hover:bg-gray-50">
                  <td className="px-4 py-2">{log.id}</td>
                  <td className="px-4 py-2">{log.message}</td>
                  <td
                    className={`px-4 py-2 font-semibold ${
                      log.severity === "critical"
                        ? "text-red-600"
                        : log.severity === "warning"
                        ? "text-yellow-600"
                        : "text-blue-600"
                    }`}
                  >
                    {log.severity}
                  </td>
                  <td className="px-4 py-2 text-gray-600">{log.timestamp}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default AuditLogsView;
