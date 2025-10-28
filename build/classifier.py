from flask import Flask, request, make_response
import json
import kubernetes
from kubernetes import client, config
import sys
from cloudpathlib import CloudPath
from cloudpathlib import S3Client
import tritonclient.http.aio as httpclient
import numpy as np
import os
import tarfile
import lzma
import traceback
import logging

if sys.version_info >= (3, 12, 0):
      import six
      sys.modules['kafka.vendor.six.moves'] = six.moves
from kafka import KafkaProducer
from io import BytesIO

import pickle
import base64

import re

import subprocess

import tempfile

from pathlib import Path

import threading

import rasterio

import numpy as np

import asyncio

import csv

import time

import functools

import gc

from KafkaHandler import KafkaHandler,DefaultContextFilter

def create_app():

      app = Flask(__name__)
      app.logger.setLevel(logging.DEBUG)
      handler = KafkaHandler()
      handler.setLevel(logging.INFO)
      filter = DefaultContextFilter()
      app.logger.addHandler(handler)
      app.logger.addFilter(filter)
      app.logger.info("Application Starting up...", extra={'status': 'DEBUG'})


      # This is the entry point for the SSL model from Image to Feature service.
      # It will receive a message from the Kafka topic and then do the inference on the data.
      # The result will be sent to the next service.
      # The message received should be a json with the following fields:
      # previous_component_end : A boolean that indicate if the previous component has finished.
      # S3_bucket_desc : A json with the following fields:
      # folder : The folder where the data is stored.
      # The namespace of the configmap to read is the name of the pod.
      # The name of the configmap to read is given by the URL.
      # The configmap should have a field named jsonSuperviserRequest that is a json with the following fields:
      # Topics : A json with the following fields:
      # out : The name of the kafka topic to send the result.
      # S3_bucket : A json with the following fields:
      # aws_access_key_id : The access key id of the S3 bucket.
      # aws_secret_access_key : The secret access key of the S3 bucket.
      # s3-bucket_name : The name of the S3 bucket.
      # region_name : The name of the region of the S3 bucket.
      # endpoint_url : The endpoint url of the S3 bucket.
      # ML : A json with the following fields:
      # need-to-resize : A boolean that indicate if the data need to be resized.

      @app.route('/<name>', methods=['POST'])
      def classifier(name):
            # TODO : Debugging message to remove in production.
            # Message received.
            response=None

            try:
                  raw_data = request.data

                  def threadentry(raw_data):
                        config.load_incluster_config()
                        api_instance = client.CoreV1Api()
                        configmap_name = str(name)
                        configmap_namespace = 'uc6'
                        api_response = api_instance.read_namespaced_config_map(configmap_name, configmap_namespace)
                        json_data_request = json.loads(raw_data)
                        json_data_configmap =json.loads(str(api_response.data['jsonSuperviserRequest']))
                        workflow_name = json_data_configmap.get('workflow_name', '')
                        bootstrapServers =api_response.data['bootstrapServers']
                        component_name = json_data_configmap['ML']['component_name']
                        while True:
                              try:
                                    Producer=KafkaProducer(bootstrap_servers=bootstrapServers,value_serializer=lambda v: json.dumps(v).encode('utf-8'),key_serializer=str.encode)
                                    break
                              except Exception as e:
                                    app.logger.error('Got exception while connecting to Kafka '+str(e)+'\n'+traceback.format_exc()+' retrying', extra={'status': 'CRITICAL'})
                        try:
                              logger_workflow = logging.LoggerAdapter(app.logger, {'source': component_name,'workflow_name': workflow_name,'producer':Producer},merge_extra=True)
                              logger_workflow.info('Starting Workflow',extra={'status':'START'})
                              logger_workflow.debug('Reading json data request'+str(json_data_request), extra={'status': 'DEBUG'})
                              logger_workflow.debug('Reading json data configmap'+str(json_data_configmap), extra={'status': 'DEBUG'})
                              if not(json_data_request['previous_component_end'] == 'True' or json_data_request['previous_component_end']):
                                    class PreviousComponentEndException(Exception):
                                          pass
                                    raise PreviousComponentEndException('Previous component did not end correctly')

                              kafka_out = json_data_configmap['Topics']["out"]
                              s3_access_key = json_data_configmap['S3_bucket']['aws_access_key_id']
                              s3_secret_key = json_data_configmap['S3_bucket']['aws_secret_access_key']
                              s3_bucket_output = json_data_configmap['S3_bucket']['s3-bucket-name']
                              s3_region = json_data_configmap['S3_bucket']['region_name']
                              s3_region_endpoint = json_data_configmap['S3_bucket']['endpoint_url']
                              s3_path = json_data_request['S3_bucket_desc']['folder']
                              s3_file = json_data_request['S3_bucket_desc'].get('filename',None)
                  
                              #min_value= np.array([-3.27219640e-11,4.63616730e+02]).reshape(1,1,-1,1,1).astype(np.float32)
                              #max_value= np.array([1.05710514e-01,5.43290894e+02]).reshape(1,1,-1,1,1).astype(np.float32)
                              
                              logger_workflow.debug('All json data read', extra={'status': 'INFO'})

                              clientS3 = S3Client(aws_access_key_id=s3_access_key, aws_secret_access_key=s3_secret_key,endpoint_url=s3_region_endpoint)
                              clientS3.set_as_default_client()

                              logger_workflow.debug('Client is ready', extra={'status': 'INFO'})

                              
                              
                              cp = CloudPath("s3://"+s3_bucket_output+'/'+s3_path, client=clientS3)
                              cpOutput = CloudPath("s3://"+s3_bucket_output+'/result-uc6-classifier/')
                              logger_workflow.debug("path is s3://"+s3_bucket_output+'/result-uc6-classifier/', extra={'status': 'DEBUG'})

                              with cpOutput.joinpath('log.txt').open('w') as fileOutput:
                                    listData=[]
                                    for folder in cp.rglob('*.pkl'):
                                          data=pickle.load(folder.open('rb'))
                                          if isinstance(data, dict) and 'input_sequence' in data and 'nodata_mask' in data and 'full_transform' in data:
                                                input_sequence = data['input_sequence']
                                                if isinstance(input_sequence, np.ndarray):
                                                      if input_sequence.ndim == 4:
                                                            if input_sequence.shape[0] == 10 and input_sequence.shape[1] == 4:
                                                                  nodata_mask = data['nodata_mask']
                                                                  if isinstance(nodata_mask, np.ndarray):
                                                                        if nodata_mask.ndim == 2 and nodata_mask.shape == input_sequence.shape[2:]:
                                                                              full_transform = data['full_transform']
                                                                              if isinstance(full_transform, rasterio.transform.Affine):
                                                                                    listData.append({'path': folder, 'data': data})
                                    file_timings=[]
                                    total_number=len(listData)
                                    for file_number,data in enumerate(listData):
                                          file_start_time=time.time()
                                          toInfer=[]
                                          data_data=data['data']
                                          input=data_data['input_sequence']
                                          nodata_mask=data_data['nodata_mask']
                                          full_transform=data_data['full_transform']
                                          xshape=input.shape[2]
                                          yshape=input.shape[3]
                                          path=data['path']
                                          for i in range(0,xshape):
                                                for j in range(0,yshape):
                                                      if not(nodata_mask[i,j]):
                                                            dic={}
                                                            dic['data']=input[:,:,i,j]
                                                            dic['i']=i
                                                            dic['j']=j
                                                            toInfer.append(dic)
                                          logger_workflow.debug('Starting inference', extra={'status': 'DEBUG'})
                                          logger_workflow.debug('Number of data to infer '+str(len(toInfer)), extra={'status': 'DEBUG'})
                                          asyncio.run(doInference(toInfer,logger_workflow,file_timings,file_number,total_number))
                                          logger_workflow.debug('Inference done', extra={'status': 'DEBUG'})
                                          output=np.zeros((xshape,yshape),dtype=np.float32)
                                          output.fill(-1.0)
                                          for element in toInfer:
                                                i=element['i']
                                                j=element['j']
                                                result=element['result']
                                                output[i,j]=result
                                          rel_path=path.relative_to(cp)
                                          output_path = cpOutput.joinpath(str(rel_path)+'_result.tiff')
                                          output_path.parent.mkdir(parents=True, exist_ok=True)
                                          with output_path.open('wb') as outputFile, rasterio.io.MemoryFile() as memfile:
                                                logger_workflow.debug('height '+str(xshape)+' width '+str(yshape), extra={'status': 'DEBUG'})
                                                logger_workflow.debug('type height '+str(type(xshape))+' type width '+str(type(yshape)),extra={'status':'DEBUG'})
                                                with memfile.open(driver="GTiff", crs="+proj=latlong", transform=full_transform, height=xshape, width=yshape, count=1, dtype=output.dtype,nodata=-1) as dst:
                                                      dst.update_tags(1, description=f"Locust suitability index")
                                                      dst.write(output, 1)
                                                outputFile.write(memfile.read())
                                          file_end_time=time.time()
                                          file_timings.append(file_end_time-file_start_time)

                                    
                                    logger_workflow.debug('Connecting to Kafka', extra={'status': 'DEBUG'})

                                    response_json ={
                                    "previous_component_end": "True",
                                    "S3_bucket_desc": {
                                          "folder": "result-uc6-classifier","filename": ""
                                    },
                                    "meta_information": json_data_request.get('meta_information',{})}
                                    Producer.send(kafka_out,key='key',value=response_json)
                                    Producer.flush()
                        except Exception as e:
                              logger_workflow.error('Got exception '+str(e)+'\n'+traceback.format_exc()+'\n'+'So we are ignoring the message', extra={'status': 'CRITICAL'})
                              return
                        logger_workflow.info('workflow finished successfully',extra={'status':'SUCCESS'})
                  thread = threading.Thread(target=threadentry, args=(raw_data,))
                  thread.start()
                  response = make_response({
                              "msg": "Started the process"
                              })
            except Exception as e:
                  app.logger.error('Got exception '+str(e)+'\n'+traceback.format_exc()+'\n'+'So we are ignoring the message', extra={'status': 'CRITICAL'})
                  # HTTP answer that the message is malformed. This message will then be discarded only the fact that a sucess return code is returned is important.
                  response = make_response({
                  "msg": "There was a problem ignoring"
                  })
            return response

      # This function is used to do the inference on the data.
      # It will connect to the triton server and send the data to it.
      # The result will be returned.
      # The data should be a numpy array of shape (1,10,120,120) and type float32.
      # The result will be a json with the following fields:
      # model_name : The name of the model used.
      # outputs : The result of the inference.
      async def doInference(toInfer,logger_workflow,file_timings,file_number,total_number):

            triton_client = httpclient.InferenceServerClient(url="default-inference.uc6.svc.cineca-inference-server.local", verbose=False,conn_timeout=10000000000,conn_limit=None,ssl=False)
            nb_Created=0
            nb_InferenceDone=0
            nb_Postprocess=0
            nb_done_instance=0
            list_postprocess=set()
            list_task=set()
            last_throw=0
            lookup={}
            nb_line_done=0
            nb_line_total=len(toInfer)

            async def consume(task):
                  try:
                        if task[0]>0:
                              count=task[1]
                              inputs = []
                              outputs = []
                              data=toInfer[count]["data"]
                              input=np.zeros([task[0],data.shape[0],data.shape[1]],dtype=np.float32)
                              for i in range(0,task[0]):
                                    data=toInfer[count+i]["data"]
                                    input[i]=data
                              inputs.append(httpclient.InferInput('input',input.shape, "FP32"))
                              del data
                              inputs[0].set_data_from_numpy(input, binary_data=True)
                              outputs.append(httpclient.InferRequestedOutput('output', binary_data=True))
                              results = await triton_client.infer('maxent',inputs,outputs=outputs)
                              gc.collect()
                              return (task,results)
                  except Exception as e:
                        logger_workflow.debug('Got exception in inference '+str(e)+'\n'+traceback.format_exc(), extra={'status': 'WARNING'})
                        nonlocal last_throw
                        last_throw=time.time()
                        return await consume(task)
                  
            async def postprocess(task,results):
                  nb=task[0]
                  result=results.as_numpy('output')
                  nonlocal nb_line_done
                  for i in range(0,nb):
                        toInfer[task[1]+i]["result"]=result[i][0]
                  nb_line_done+=nb

            def postprocessTask(task):
                  list_task.discard(task)
                  new_task=asyncio.create_task(postprocess(*task.result()))
                  list_postprocess.add(new_task)
                  def postprocessTaskDone(task2):
                        nonlocal nb_Postprocess
                        nb_Postprocess+=1
                        nonlocal nb_done_instance
                        nb_done_instance+=task.result()[0][0]
                        list_postprocess.discard(task2)
                  new_task.add_done_callback(postprocessTaskDone)
                  nonlocal nb_InferenceDone
                  nb_InferenceDone+=1

            def producer():
                  total=len(toInfer)
                  count=0
                  while total-count>=255:
                        yield (255,count)
                        count=count+255
                  while total-count>=1:
                        yield (1,count)
                        count=count+1

            last_shown=time.time()
            start=time.time()-60
            for item in producer():
                  while time.time()-last_throw<30 or nb_Created-nb_InferenceDone>5 or nb_Postprocess-nb_InferenceDone>5:
                        await asyncio.sleep(0)
                  task=asyncio.create_task(consume(item))
                  list_task.add(task)
                  task.add_done_callback(postprocessTask)
                  nb_Created+=1
                  if time.time()-last_shown>60:
                        last_shown=time.time()
                        logger_workflow.debug('done instance '+str(nb_done_instance)+'Inference done value '+str(nb_InferenceDone)+' postprocess done '+str(nb_Postprocess)+ ' created '+str(nb_Created), extra={'status': 'DEBUG'})
                        elapsed_time = time.time() - start + 60  # Add back the 60s offset
                        if nb_line_done > 0:
                              rate = nb_line_done / elapsed_time
                              remaining_lines_current_file = nb_line_total - nb_line_done
                              estimated_remaining_seconds_current_file = remaining_lines_current_file / rate if rate > 0 else 0
                              # Estimate time for remaining files using actual timing data from completed files
                              if len(file_timings) > 0:
                                    # Use average of completed files for better accuracy
                                    avg_time_per_file = sum(file_timings) / len(file_timings)
                              else:
                                    # Fallback to current file estimate if no completed files yet
                                    avg_time_per_file = elapsed_time
                              remaining_files = total_number - file_number - 1
                              estimated_remaining_seconds_other_files = remaining_files * avg_time_per_file
                              total_estimated_remaining = estimated_remaining_seconds_current_file + estimated_remaining_seconds_other_files
                              hours = int(total_estimated_remaining // 3600)
                              minutes = int((total_estimated_remaining % 3600) // 60)
                              seconds = int(total_estimated_remaining % 60)
                              time_estimate = f"{hours}h {minutes}m {seconds}s" if hours > 0 else f"{minutes}m {seconds}s"
                        elif nb_line_done == 0 and len(file_timings) > 0:
                              # If no lines done yet, use average of completed files
                              avg_time_per_file = sum(file_timings) / len(file_timings)
                              remaining_files = total_number - file_number
                              estimated_remaining_seconds_other_files = remaining_files * avg_time_per_file
                              hours = int(estimated_remaining_seconds_other_files // 3600)
                              minutes = int((estimated_remaining_seconds_other_files % 3600) // 60)
                              seconds = int(estimated_remaining_seconds_other_files % 60)
                              time_estimate = f"{hours}h {minutes}m {seconds}s" if hours > 0 else f"{minutes}m {seconds}s"
                        else:
                              time_estimate = "calculating..."
                        logger_workflow.info('Progress file '+str(file_number)+'/'+str(total_number)+' : '+str(nb_line_done)+'/' +str(nb_line_total)+' patches ('+str((nb_line_done*100)//nb_line_total)+' %) - Est. remaining: '+time_estimate, extra={'status': 'INFO', 'overwrite':True})

            while nb_InferenceDone-nb_Created>0 or nb_Postprocess-nb_InferenceDone>0:
                  await asyncio.sleep(0)
            await asyncio.gather(*list_task,*list_postprocess)
            logger_workflow.debug('Inference done', extra={'status': 'DEBUG'})
            await triton_client.close()
      return app