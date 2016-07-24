function [] = visualisationAllCiphers2D(measurementFolder)

    %take all files starting with 'log' and with extension '.txt'
    extension = 'log*.txt';
    measurementFolderPattern = strcat(measurementFolder,extension);
    %get list of all log files
    logfiles = dir(measurementFolderPattern);
    
    
    %extract data from all logfiles
    data = cell(length(logfiles));
    cipherList = {};

    for i = 1:length(logfiles)
        filename = strcat(measurementFolder, logfiles(i).name);
        log = fopen(filename, 'r');
        data{i} = extractDataFromLogfile(log);
        fclose(log);
        
        %extract cipher name from filename for legend
        cipher = textscan(filename,'%s','delimiter','_');
        optimization = cipher{1}{3};
        optimization = optimization(1:end-4);
        cipherList{i} = strcat(cipher{1}(2), '_', optimization);
        %cipherList{i} = cipher(2);
    end
    numberofciphers = length(logfiles);


    cipherList;
    cipherList{1}
    
    associatedDataLengths = [0];%,128,256,384,512,640,768,896,1024,1152,1280,1408,1536,1664,1792,1920,2048];
    messageLengths = [0,128];%,256,384,512,640,768,896,1024,1152,1280,1408,1536,1664,1792,1920,2048];
    
    %plot all ciphers for a fixed AD length over all msg length's
    %plotWithFixedADlen(data, associatedDataLengths, numberofciphers, cipherList);
    
    %plot all ciphers for a fixed AD length over all msg length's
    %plotWithFixedMSGlen(data, messageLengths, numberofciphers, cipherList);

    plotBarGraph(data, messageLengths, numberofciphers, cipherList);
    %plotBarhGraph(data, messageLengths, numberofciphers, cipherList);
    
end

function [parameters] = extractDataFromLogfile(log)
    % parse number of testcases from first line
    input = textscan(log,'%s',1,'delimiter',';');
    nroftestcases = textscan(input{1}{1}, '%s %d','delimiter','=');
    nroftestcases = nroftestcases(2);
    nroftestcases = nroftestcases{1};

    parameters = struct('nroftestcases', nroftestcases);
    
    data = cell(double(nroftestcases));
    numberofadentries = cell(double(nroftestcases));
    numberofmsgentries = cell(double(nroftestcases));
    for i = 1:nroftestcases

        % for each testcase parse number of associated data entries and 
        % number of message entries
        trash = textscan(log,'%s',3,'delimiter',';');
        
        numberofadentries{i} = textscan(trash{1}{2}, '%s %d','delimiter','=');
        numberofadentries{i} = numberofadentries{i}{2};

        numberofmsgentries{i} = textscan(trash{1}{3}, '%s %d','delimiter','=');
        numberofmsgentries{i} = numberofmsgentries{i}{2};
        
        % for each testcase trash second line with metadata
        % extract lines into data cellarray
        textscan(log,'%s',4,'delimiter',';');
        data{i} = textscan(log,'%s %f %f %f',numberofadentries{i}*numberofmsgentries{i},'delimiter',';');
    end
    
    parameters.numberofadentries = numberofadentries;
    parameters.numberofmsgentries = numberofmsgentries;
    parameters.data = data;    
end

function [] = plotWithFixedMSGlen(dataAllCiphers, messageLengths, numberofciphers, cipherList)

    for j = 1:length(messageLengths)
        for i = 1:length(dataAllCiphers)
            figure;
            for k  = 1:nroftestcases
                plot(dataAllCiphers{i}{3}(1:numberofmsgentries), dataAllCiphers{i}{2}(1:numberofmsgentries), 'Color', color(i), 'Marker', 'd');
                hold all;
        
                title('Benchmarking with fixed Message length')
                xlabel('Associated Data (bytes)')
                ylabel('Performance (cpb)')
    
                %legend_str = {};
                %for i=1:num_val
                %    legend_str{i} = data{i}{1}{1};
                %end
                %legend(legend_str{:});
    
                axis([0, 2048, 7, 40]);
                set(gca,'XTick',[0:128:2048]);
                set(gca,'YTick',[7:5:40]);
            end
        end
    end
end

function [] = plotWithFixedADlen(dataAllCiphers, associatedDataLengths, numberofciphers, cipherList)

    figure;
    for i = 1:numberofciphers % for every cipher
    for k = 1:(dataAllCiphers{1}.nroftestcases-1) % for every testcase (exclude testcases with fixed values
        for j = 1:length(associatedDataLengths) % for every fixed ad length
            %figure;
            yHighestValue = 0;
            yLowestValue = 1000000;
            yTickArray = [];


                startvalue = (((associatedDataLengths(j)/128)*dataAllCiphers{i}.numberofadentries{k})+1);
                endvalue = (((associatedDataLengths(j)/128)*dataAllCiphers{i}.numberofadentries{k}))+dataAllCiphers{i}.numberofmsgentries{k};
                                
                semilogy(dataAllCiphers{i}.data{k}{3}(startvalue:endvalue), dataAllCiphers{i}.data{k}{2}(startvalue:endvalue), 'Marker', 'd');
                
                
                A = dataAllCiphers{i}.data{k}{2}(startvalue:endvalue);
                if isinf(max(A))    % if max value is inf go for second highest value
                    if max(A(A~=max(A))) > yHighestValue
                        yHighestValue = max(A(A~=max(A)));
                        yTickArray(end+1) = yHighestValue;
                    end
                else
                    if max(A) > yHighestValue
                        yHighestValue = max(A);
                        yTickArray(end+1) = yHighestValue;
                    end
                end
                if min(dataAllCiphers{i}.data{k}{2}(startvalue:endvalue)) < yLowestValue
                    yLowestValue = min(dataAllCiphers{i}.data{k}{2}(startvalue:endvalue));
                    yTickArray(end+1) = yLowestValue;
                end
                
                for d = 1:dataAllCiphers{i}.numberofmsgentries{k}
                    if ~mod(d, 5)
                        yTickArray(end+1) = dataAllCiphers{i}.data{k}{2}(startvalue+(d-1));
                    end 
                end
            end
            
            %yHighestValue
            %yLowestValue
            
            %title('Benchmarking with fixed Associated Data length')
            xlabel('Message length (bytes)')
            ylabel('Performance (cpb)')
            
            if yLowestValue - 10 > 0
                yLowestValue = yLowestValue-10;
            else 
                yLowestValue = 0;
            end
            yTickArray = sort(unique(yTickArray))
    
            axis([0, 2048, yLowestValue, yHighestValue + (yHighestValue/2)]);
            set(gca,'XTick',0:128:2048);
            set(gca,'YTick',yTickArray);
            
            
        end
        
        lh=findall(gcf,'tag','legend');
        set(lh,'location','northeastoutside');
        legend([cipherList{i}], 'Interpreter', 'none');
    end
    hold all;
end

function [] = plotBarGraph(dataAllCiphers, messageLengths, numberofciphers, cipherList)

    ciphers = {};
    for i = 1:numberofciphers
      ciphers{i} = textscan(char(cipherList{i}),'%s','delimiter','_');
      ciphers{i}{1}(1)
    end
    
    
    print_figure = 1;
    values = [];
    for i = 1:numberofciphers % for every cipher
    
      len = 0;
      if (i+1 <= numberofciphers)
        if length(char(ciphers{i}{1}(1))) < length(char(ciphers{i+1}{1}(1)))
          len = length(char(ciphers{i+1}{1}(1)));
        else
          len = length(char(ciphers{i}{1}(1)));
        end
      end
       
      if (i+1 <= numberofciphers) && strncmp(char(ciphers{i}{1}(1)), char(ciphers{i+1}{1}(1)), len)
        print_figure = 0;
        
        s = size(values);
        if s(1) >= 1
            values(:, s(2) + 1) = dataAllCiphers{i}.data{2}{2};
        else
          values = dataAllCiphers{i}.data{2}{2};
        end
      else
        print_figure = 1;
        
        s = size(values);
        if s(1) >= 1
          values(:, s(2) + 1) = dataAllCiphers{i}.data{2}{2};
        else
          values = dataAllCiphers{i}.data{2}{2};
        end
      end


      if print_figure
      figure;
      
      values
      
      format long;
      bar(values, 'stacked');

      set(gca,'fontsize',22);
      xlabel('Message Size');
      ylabel('Performance (cpb)')
      %set(gca,'Ytick', sort(dataAllCiphers{i}.data{5}{2}));
      set(gca, 'XTickLabel', num2str(sort(dataAllCiphers{i}.data{2}{3})));
      %set(gca,'YScale','log');
      
      s = size(values);
      for u = 1:s(2)
        y = values(:, u)
        t = text([1,2,3,4,5,6], y, num2str(y),'HorizontalAlignment','center','VerticalAlignment','bottom');
        set(t, 'FontSize', 22);
      end
      
%{
      P=findobj(gca,'type','patch');
      C=['w','k','m','g'];
      
      for n = 1 : length(P)
        set(P(n),'facecolor',C(n));
      end
      %}
      values = [];
      hold all;
      end
    end
end

function [] = plotBarhGraph(dataAllCiphers, messageLengths, numberofciphers, cipherList)

    values_ssh = [];
    values_tls = [];
    
    c = 0;
    for k = 1:(dataAllCiphers{1}.nroftestcases) % for every testcase
        for i = 1:numberofciphers % for every cipher
            c = c + 1;
            
            %strncmp(cipherList{i}, 'a', 1)
            values_ssh(c) = dataAllCiphers{i}.data{1}{2}(1); % ssh
            values_tls(c) = dataAllCiphers{i}.data{1}{2}(2); % tls
            
        end
    end
  
  obj = struct();
  obj.values = values_tls;
  obj.ciphers = cipherList;
  
  obj = sortValNam(obj);
  
  figure;
  barh(obj.values + 1, 'FaceColor',[0.5, 0.5, 0.5]); % tls +1, ssh nope
  hold all;
        
  set(gca,'fontsize',12);
  %set(gca,'Color',[1,0.4,0.6])
        
  xlabel('Performance (cpb)')
  set(gca, 'XGrid', 'on');
  set(gca,'XScale','log');
  set(gca,'XLim', [0, 10000]); % tls 10000, ssh 28000
  %set(gca,'Xtick', [1:1000:100]);
  %set(gca,'Xtick', unique(ceil(obj.values)));
  
  set(gca,'Ytick', [1:30]);
  set(gca,'YLim', [0,31]);
  set(gca,'YTickLabel', [obj.ciphers{:}]);
  
  %PlotAxisAtOrigin(0,0);
  
  y = [0:length(obj.values)-1];
  y = y + 0.6;
  %shift = exp([1:0.2167:7.5])
  %shift = exp(9)
  %x = obj.values + shift
  x = [];
  for i = 1:30
   x(i) = max(obj.values) + 1800; % tls 1800, ssh 10000
  end
  t = text(x,y,num2str(obj.values(:)),'HorizontalAlignment','center','VerticalAlignment','bottom');
  set(t, 'FontSize', 10);
  
  %ylabel('')
end


function obj = sortValNam(obj)
  n =length(obj.values);
  swapped = 1;
  
  while swapped == 1
    swapped = 0;
    for i = 2:n

       if obj.values(i-1) > obj.values(i)
          temp_value =  obj.values(i-1);
          temp_cipher =  obj.ciphers(i-1);
          
          obj.values(i-1) = obj.values(i);
          obj.ciphers(i-1) = obj.ciphers(i);
          
          obj.values(i) = temp_value;
          obj.ciphers(i) = temp_cipher;
          swapped = 1;
       end
    end
  end
end