from flask import Flask, request, make_response
import uuid
import json
import kubernetes
from kubernetes import client, config
import sys
from cloudpathlib import CloudPath
from cloudpathlib import S3Client
import tritonclient.http.aio as httpclient
import numpy as np
from kafka import KafkaProducer
import os
import tarfile
import lzma
import traceback
import logging

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

def create_app():

      app = Flask(__name__)

      logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
      kafka_logger = logging.getLogger('kafka')
      kafka_logger.setLevel(logging.CRITICAL)
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

      def log(outfile,message):
            app.logger.warning(message)
            if outfile is not None:
                  timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                  outfile.write(timestamp+':'+message+'\n')

      @app.route('/<name>', methods=['POST'])
      def classifier(name):
            app.logger.warning('received request')
            # TODO : Debugging message to remove in production.
            # Message received.
            response=None
            try:
                  config.load_incluster_config()
                  api_instance = client.CoreV1Api()
                  configmap_name = str(name)
                  configmap_namespace = 'uc6'
                  app.logger.warning('Namespace '+str(configmap_namespace))
                  api_response = api_instance.read_namespaced_config_map(configmap_name, configmap_namespace)
                  json_data_request = json.loads(request.data)
                  json_data_configmap =json.loads(str(api_response.data['jsonSuperviserRequest']))
                  bootstrapServers =api_response.data['bootstrapServers']
                  Producer=KafkaProducer(bootstrap_servers=bootstrapServers,value_serializer=lambda v: json.dumps(v).encode('utf-8'),key_serializer=str.encode)      
                  app.logger.warning('Reading json data request'+str(json_data_request))
                  app.logger.warning('Reading json data configmap'+str(json_data_configmap))
                  assert json_data_request['previous_component_end'] == 'True' or json_data_request['previous_component_end']
                  kafka_out = json_data_configmap['Topics']["out"]
                  s3_access_key = json_data_configmap['S3_bucket']['aws_access_key_id']
                  s3_secret_key = json_data_configmap['S3_bucket']['aws_secret_access_key']
                  s3_bucket_output = json_data_configmap['S3_bucket']['s3-bucket-name']
                  s3_region = json_data_configmap['S3_bucket']['region_name']
                  s3_region_endpoint = json_data_configmap['S3_bucket']['endpoint_url']
                  s3_path = json_data_request['S3_bucket_desc']['folder']
                  s3_file = json_data_request['S3_bucket_desc'].get('filename',None)
                  min_value= np.array([4.63616730e+02,-3.27219640e-11]).reshape(1,1,-1,1,1).astype(np.float32)
                  max_value= np.array([5.43290894e+02, 1.05710514e-01]).reshape(1,1,-1,1,1).astype(np.float32)

                  log_function = functools.partial(log,None)

                  #min_value= np.array([-3.27219640e-11,4.63616730e+02]).reshape(1,1,-1,1,1).astype(np.float32)
                  #max_value= np.array([1.05710514e-01,5.43290894e+02]).reshape(1,1,-1,1,1).astype(np.float32)

                  def threadentry():
                        app.logger.warning('All json data read')

                        clientS3 = S3Client(aws_access_key_id=s3_access_key, aws_secret_access_key=s3_secret_key,endpoint_url=s3_region_endpoint)
                        clientS3.set_as_default_client()

                        app.logger.warning('Client is ready')

                        
                        
                        cp = CloudPath("s3://"+s3_bucket_output+'/'+s3_path, client=clientS3)
                        cpOutput = CloudPath("s3://"+s3_bucket_output+'/result-uc6-classifier/')
                        app.logger.warning("path is s3://"+s3_bucket_output+'/result-uc6-classifier/')
                        def fatalError(message):
                              log_function(message)
                              with cpOutput.joinpath('fatal.txt').open('w') as fileOutput:
                                    fileOutput.write(message)

                        with cpOutput.joinpath('log.txt').open('w') as fileOutput:
                              log_function = functools.partial(log,fileOutput)
                              meta=None
                              def read_data(folder):
                                    with folder.open('rb') as fileBand, rasterio.io.MemoryFile(fileBand) as memfile:
                                          with memfile.open(driver="GTiff",sharing=False) as band_file:
                                                nonlocal meta
                                                meta=band_file.meta
                                                result=band_file.read()
                                                return result
                              
                              array=[]
                              listName=[]
                              for folder in cp.iterdir():
                                    if folder.name.endswith('.tiff') or folder.name.endswith('.tif'):
                                          listName.append(folder)
                              for folder in listName[-4:]:
                                    array.append(read_data(folder))
                              nparray=np.stack(array)
                              shapeArray=nparray.shape
                              xshape=shapeArray[2]
                              yshape=shapeArray[3]
                              nparray=np.expand_dims(nparray.astype(np.float32),axis=0)
                              resultArray=np.zeros([xshape,yshape],dtype=np.float32)
                              count=np.zeros([xshape,yshape],dtype=np.float32)
                              if shapeArray[0]!=4:
                                    fatalError('Invalid input shape, got '+str(shapeArray) + ' instead of (4,x,y). This is likely due to the fact that not enough tiff files are present in the folder. 4 are needed. Exiting.')
                                    return
                              toInfer=[]
                              for i in range(0,xshape-11,2):
                                    for j in range(0,yshape-11,2):
                                          #subarray=nparray[:,:,[0,2],i:i+12,j:j+12]
                                          dic={}
                                          #dic["data"]=(np.expand_dims(subarray.astype(np.float32),axis=0)-min_value)/(max_value-min_value)
                                          dic["data"]=nparray
                                          dic["i"]=i
                                          dic["j"]=j
                                          toInfer.append(dic)
                                    if yshape%12!=0:
                                          j=yshape-12
                                          #subarray=nparray[:,:,[0,2],i:i+12,j:yshape]
                                          dic={}
                                          #dic["data"]=(np.expand_dims(subarray.astype(np.float32),axis=0)-min_value)/(max_value-min_value)
                                          dic["data"]=nparray
                                          dic["i"]=i
                                          dic["j"]=j
                                          toInfer.append(dic)
                              if xshape%12!=0:
                                    i=xshape-12
                                    for j in range(0,yshape-11):
                                          #subarray=nparray[:,:,[0,2],i:xshape,j:j+12]
                                          dic={}
                                          #dic["data"]=(np.expand_dims(subarray.astype(np.float32),axis=0)-min_value)/(max_value-min_value)
                                          dic["data"]=nparray
                                          dic["i"]=i
                                          dic["j"]=j
                                          toInfer.append(dic)
                                    if yshape%12!=0:
                                          j=yshape-12
                                          #subarray=nparray[:,:,[0,2],i:xshape,j:yshape]
                                          dic={}
                                          #dic["data"]=(np.expand_dims(subarray.astype(np.float32),axis=0)-min_value)/(max_value-min_value)
                                          dic["data"]=nparray
                                          dic["i"]=i
                                          dic["j"]=j
                                          toInfer.append(dic)
                              log_function('Starting inference')
                              log_function('Number of data to infer '+str(len(toInfer)))
                              asyncio.run(doInference(toInfer,log_function,min_value,max_value))
                              log_function('Inference done')
                              for requestElem in toInfer:
                                    result_subarray=requestElem["result"]
                                    i=requestElem["i"]
                                    j=requestElem["j"]
                                    for i2 in range(0,12):
                                          for j2 in range(0,12):
                                                resultArray[i+i2,j+j2]=resultArray[i+i2,j+j2]+result_subarray
                                                count[i+i2,j+j2]=count[i+i2,j+j2]+1.0

                              resultArray=resultArray/count

                              transform=rasterio.transform.AffineTransformer(meta['transform'])

                              outputPath=cpOutput.joinpath('classifier-result.csv')
                              with outputPath.open('w') as outputFile:
                                    writer = csv.writer(outputFile)
                                    writer.writerow(['latitude','longitude','probability'])
                                    for i in range(0,xshape):
                                          for j in range(0,yshape):
                                                coord=transform.xy(i,j)
                                                writer.writerow([coord[0],coord[1],resultArray[i,j]])

                              jsonData={}
                              jsonData['data']=resultArray.tolist()
                              jsonData['shape']=resultArray.shape
                              jsonData['type']=str(resultArray.dtype)
                              meta['crs']=meta['crs'].to_string()
                              jsonData['metadata']=meta

                              outputPath=cpOutput.joinpath('classifier-result.json')
                              with outputPath.open('w') as outputFile:
                                    json.dump(jsonData, outputFile)

                              outputPath=cpOutput.joinpath('classifier-result.tiff')
                              with outputPath.open('wb') as outputFile, rasterio.io.MemoryFile() as memfile:
                                    log_function('height '+str(xshape)+' weight '+str(yshape))
                                    log_function('type height '+str(type(xshape))+' type weight '+str(type(yshape)))
                                    log_function('crs '+str(meta['crs']))
                                    with memfile.open(driver="GTiff",crs=meta['crs'],transform=meta['transform'],height=xshape,width=yshape,count=1,dtype=resultArray.dtype) as dst:
                                          dst.write(resultArray,1)
                                    outputFile.write(memfile.read())
                              
                              log_function('Connecting to Kafka')

                              response_json ={
                              "previous_component_end": "True",
                              "S3_bucket_desc": {
                                    "folder": "result-uc6-classifier","filename": ""
                              },
                              "meta_information": json_data_request.get('meta_information',{})}
                              Producer.send(kafka_out,key='key',value=response_json)
                              Producer.flush()
                  thread = threading.Thread(target=threadentry)
                  thread.start()
                  response = make_response({
                              "msg": "Started the process"
                              })

            except Exception as e:
                  app.logger.warning('Got exception '+str(e))
                  app.logger.warning(traceback.format_exc())
                  app.logger.warning('So we are ignoring the message')
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
      async def doInference(toInfer,log_function,min_value,max_value):

            triton_client = httpclient.InferenceServerClient(url="default-inference.uc6.svc.cineca-inference-server.local", verbose=False,conn_timeout=10000000000,conn_limit=None,ssl=False)
            nb_Created=0
            nb_InferenceDone=0
            nb_Postprocess=0
            nb_done_instance=0
            list_postprocess=set()
            list_task=set()
            last_throw=0
            lookup={}

            async def consume(task):
                  try:
                        if task[0]==1000:
                              count=task[1]
                              inputs = []
                              outputs = []
                              iCord=toInfer[count]["i"]
                              jCord=toInfer[count]["j"]
                              data=toInfer[count]["data"][:,:,[0,2],iCord:iCord+12,jCord:jCord+12]
                              input=np.zeros([1000,data.shape[1],data.shape[2],data.shape[3],data.shape[4]],dtype=np.float32)
                              #log_function('input shape '+str(input.shape))
                              for i in range(0,1000):
                                    iCord=toInfer[count+i]["i"]
                                    jCord=toInfer[count+i]["j"]
                                    data=(toInfer[count+i]["data"][:,:,[0,2],iCord:iCord+12,jCord:jCord+12]-min_value)/(max_value-min_value)
                                    input[i]=data[0]
                              inputs.append(httpclient.InferInput('input',input.shape, "FP32"))
                              del data
                              inputs[0].set_data_from_numpy(input, binary_data=True)
                              outputs.append(httpclient.InferRequestedOutput('probability', binary_data=True))
                              results = await triton_client.infer('classifierdaily1000',inputs,outputs=outputs)
                              gc.collect()
                              return (task,results)
                                    #results=results.as_numpy('probability')
                                    #for i in range(0,1000):
                                          #toInfer[count+i]["result"]=results[i][0]
                        elif task[0]==1:
                              count=task[1]
                              inputs=[]
                              outputs=[]
                              iCord=toInfer[count]["i"]
                              jCord=toInfer[count]["j"]
                              data=(toInfer[count]["data"][:,:,[0,2],iCord:iCord+12,jCord:jCord+12]-min_value)/(max_value-min_value)
                              inputs.append(httpclient.InferInput('input',data.shape, "FP32"))
                              inputs[0].set_data_from_numpy(data, binary_data=True)
                              del data
                              outputs.append(httpclient.InferRequestedOutput('probability', binary_data=True))
                              results = await triton_client.infer('classifierdaily1',inputs,outputs=outputs)
                              return (task,results)
                                    #toInfer[count]["result"]=results.as_numpy('probability')[0][0]
                  except Exception as e:
                        log_function('Got exception '+str(e))
                        log_function(traceback.format_exc())
                        nonlocal last_throw
                        last_throw=time.time()
                        return await consume(task)
                  
            async def postprocess(task,results):
                  if task[0]==1:
                        result=results.as_numpy('probability')[0][0]
                        toInfer[task[1]]["result"]=result
                  if task[0]==1000:
                        result=results.as_numpy('probability')
                        for i in range(0,1000):
                              toInfer[task[1]+i]["result"]=result[i][0]

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
                  while total-count>=1000:
                        yield (1000,count)
                        count=count+1000
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
                        log_function('done instance '+str(nb_done_instance)+'Inference done value '+str(nb_InferenceDone)+' postprocess done '+str(nb_Postprocess)+ ' created '+str(nb_Created))
            while nb_InferenceDone-nb_Created>0 or nb_Postprocess-nb_InferenceDone>0:
                  await asyncio.sleep(0)
            await asyncio.gather(*list_task,*list_postprocess)
            log_function('Inference done')
            await triton_client.close()
      return app