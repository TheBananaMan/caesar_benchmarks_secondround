function [] = visualisation2D(filename)
    log = fopen(filename, 'r');
    normal_plot(log)    
    fclose(log);
end

function [] = normal_plot(log)

    % parse number of testcases from first line
    input = textscan(log,'%s',2,'delimiter','=');
    nroftestcases = str2num(input{1}{2});
    
    data = {};
            figure;
    for i = 1:nroftestcases

        % for each testcase parse testcase id, number of associated data 
        % entries, number of message entries
        trash = textscan(log,'%s',3,'delimiter',';');

        testcaseid = textscan(trash{1}{1},'%s %d','delimiter','=');
        testcaseid = testcaseid{2};
        %testcaseid = strsplit(trash{1}{1}, '=');
        %testcaseid = str2num(testcaseid{2});

        numberofadentries = textscan(trash{1}{2}, '%s %d','delimiter','=');
        numberofadentries = numberofadentries{2};
        %numberofadentries = strsplit(trash{1}{2}, '=');
        %numberofadentries = str2num(numberofadentries{2});

        numberofmsgentries = textscan(trash{1}{3}, '%s %d','delimiter','=');
        numberofmsgentries = numberofmsgentries{2};
        %numberofmsgentries = strsplit(trash{1}{3}, '=');
        %numberofmsgentries = str2num(numberofmsgentries{2});
        
        % for each testcase trash second line with metadata
        % extract lines into data cellarray
        trash = textscan(log,'%s',4,'delimiter',';');
        data{i} = textscan(log,'%s %f %f %f',numberofadentries*numberofmsgentries,'delimiter',';');


        color = 'krbgkk';
        plot(data{i}{3}(1:numberofmsgentries), data{i}{2}(1:numberofmsgentries), 'Color', color(i), 'Marker', 'd');
        hold all;
        
        title('Benchmarking')
        xlabel('Message (bytes)')
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
%{     
    
    data = {};
    for i=1:num_val
        trash = textscan(log,'%s',4,'delimiter',';');
        data{i} = textscan(log,'%s %d %d %d',entries,'delimiter',';');
    end
    
    color = 'krbg';
    figure;
    for i=1:num_val
        plot(data{i}{3}(1:entries), data{i}{2}(1:entries), 'Color', color(i), 'Marker', 'd');
        hold all;
    end

    title('Benchmarking')
    xlabel('Message (bytes)')
    ylabel('Performance (cpb)')
    
    legend_str = {};
    for i=1:num_val
        legend_str{i} = data{i}{1}{1};
    end
    legend(legend_str{:});
    
    axis([0, 4096, 20, 70]);
    set(gca,'XTick',[0:128:4096]);
    set(gca,'YTick',[20:2:70]);
 %}
end
