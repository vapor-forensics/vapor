'use strict';
import Chart from 'chart.js/auto';

function listToDict(list) {
  // gpt
  return list.reduce((acc, item) => {
    acc[item.date] = item.count;
    return acc;
  }, {});
}

function toDateString(dateObj) {
  return dateObj.toISOString().split('T')[0];
}

function getTimeSeriesData(start, end, data) {
  let dataDict = listToDict(data);
  let chartData = [];
  let current = new Date(start);
  while(current <= end){
    let curString = toDateString(current)
    chartData.push({
      x: curString,
      y: dataDict[curString] || 0,
    })
    current.setDate(current.getDate() + 1);
  }
  return chartData;
}

const barChartWithDates = (ctx, start, end, data, label) => {
  const chartData = getTimeSeriesData(start, end, data);
  return new Chart(ctx, {
    type: 'bar',
    data: {
      datasets: [{
        label: label,
        data: chartData,
      }]
    },
    options: {
      aspectRatio: 3,
      responsive: true,
      plugins: {
        legend: {
          display: false
        }
      },
      scales: {
        x: {
          title: {
            display: true,
            text: 'Date'
          }
        },
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: label,
          }
        }
      }
    }
  });
}

const cumulativeChartWithDates = (ctx, start, end, data, label, startValue) => {
  const chartData = getTimeSeriesData(start, end, data);
  let currentValue = startValue || 0;
  for (let row of chartData) {
    currentValue += row.y;
    row.y = currentValue;
  }
  return new Chart(ctx, {
    type: 'line',
    data: {
      datasets: [{
        label: label,
        fill: true,
        data: chartData,
      }]
    },
    options: {
      aspectRatio: 3,
      responsive: true,
      plugins: {
        legend: {
          display: false
        }
      },
      scales: {
        x: {
          title: {
            display: true,
            text: 'Date'
          }
        },
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: label,
          }
        }
      }
    }
  });

}
export const DashboardCharts = {
  barChartWithDates: barChartWithDates,
  cumulativeChartWithDates: cumulativeChartWithDates,
};
