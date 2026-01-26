package main

import (
	//"errors"
	"fmt"

	//"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"

	"time"
)

func getUptime() time.Duration {
	uptime, err := host.Uptime()

	if err != nil {
		uptime = 0
	}

	return time.Duration(uptime) * time.Second
}

func getCpuUsage() float64 {
	percentages, err := cpu.Percent(time.Second, false)

	usage := percentages[0]

	if err != nil || len(percentages) == 0 {
		usage = 0
	}

	return usage
}

func getCpuTemp() float64 {
	var temp float64
	temps, err := host.SensorsTemperatures()

	if err != nil {
		return 0
	}

	for _, t := range temps {
		if t.SensorKey == "Package id 0" || t.SensorKey == "Tctl" ||
			t.SensorKey == "coretemp_package_id_0" || t.SensorKey == "k10temp_tctl" {
			temp = t.Temperature
			return temp
		} else {
			err = fmt.Errorf("no suitable CPU temperature sensor found")
		}
	}

	return 0
}

// func getGpuStats() (float64, float64) {
// 	initRet := nvml.Init()
//
// 	if !errors.Is(initRet, nvml.SUCCESS) {
// 		return 0, 0
// 	}
//
// 	defer nvml.Shutdown()
//
// 	device, deviceRet := nvml.DeviceGetHandleByIndex(0)
// 	if !errors.Is(deviceRet, nvml.SUCCESS) {
// 		return 0, 0
// 	}
//
// 	usage, usageRet := device.GetUtilizationRates()
// 	temp, tempRet := device.GetTemperature(nvml.TEMPERATURE_GPU)
//
// 	if !errors.Is(usageRet, nvml.SUCCESS) && !errors.Is(tempRet, nvml.SUCCESS) {
// 		return 0, 0
// 	} else if !errors.Is(usageRet, nvml.SUCCESS) {
// 		return 0, float64(temp)
// 	} else if !errors.Is(tempRet, nvml.SUCCESS) {
// 		return float64(usage.Gpu), 0
// 	}
//
// 	return float64(usage.Gpu), float64(temp)
// }

func getMemoryUsage() float64 {
	v, err := mem.VirtualMemory()
	if err != nil {
		return 0
	}

	return v.UsedPercent
}
